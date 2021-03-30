/*
Copyright (C) 2013-2020 Sysdig Inc.

This file is part of sysdig.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <iostream>
#include <time.h>
#include <signal.h>
#include <assert.h>

#include <sinsp.h>
#include "scap_open_exception.h"
#include "sinsp_capture_interrupt_exception.h"
#ifdef HAS_CAPTURE
#ifndef WIN32
#include "driver_config.h"
#endif // WIN32
#endif // HAS_CAPTURE
#include "sdindexer.h"
#include "utils.h"
#include "plugin.h"

#ifdef _WIN32
#include "win32/getopt.h"
#include <io.h>
#else
#include <unistd.h>
#include <getopt.h>
#endif

static bool g_terminate = false;
static bool g_plugin_input = false;

static void usage();

//
// Helper functions
//
static void signal_callback(int signal)
{
	if(g_plugin_input)
	{
		//
		// Input plugins can get stuck at any point.
		// When we are using one, check again in few seconds and force a quit
		// if we are stuck.
		//
		if(g_terminate == true)
		{
			exit(0);
		}
		else
		{
			g_terminate = true;
#ifndef _WIN32
			alarm(2);
#endif
		}
	}
	else
	{
		g_terminate = true;
	}
}

//
// Program help
//
static void usage()
{
    printf(
"sdindexer version " SYSDIG_VERSION "\n"
"Usage: sdindexer [options] [filter]\n\n"
"Options:\n"
" -B<bpf_probe>, --bpf=<bpf_probe>\n"
"                    Enable live capture using the specified BPF probe instead of the kernel module.\n"
"                    The BPF probe can also be specified via the environment variable\n"
"                    SYSDIG_BPF_PROBE. If <bpf_probe> is left empty, sysdig will\n"
"                    try to load one from the sysdig-probe-loader script.\n"
" -h, --help         Print this page\n"
" -I <inputname>[:<inputargs>], --input <inputname>[:<inputargs>]\n"
"                    capture events using the plugin with name inputname, passing to the \n"
"                    plugin the inputargs string as parameters.\n"
"                    The format of inputargs is controller by the plugin, refer to each\n"
"                    plugin's documentation to learn about it.\n"
"                    The event sources available for capture vary depending on which \n"
"                    plugins have been installed. You can list the plugins that have been \n"
"                    loaded by using the -Il flag.\n"
" -Il, --list-inputs\n"
"                    lists the loaded plugins. Sysdig looks for plugins in the following \n"
"                    directories: ./plugins, ~/.plugins, /usr/share/sysdig/plugins.\n"
" -n <num>, --numevents=<num>\n"
"                    Stop capturing after <num> events\n"
" -P, --progress     Print progress on stderr while processing trace files\n"
" -r <readfile>, --read=<readfile>\n"
"                    Read the events from <readfile>.\n"
" -s <len>, --snaplen=<len>\n"
"                    Capture the first <len> bytes of each I/O buffer.\n"
"                    By default, the first 80 bytes are captured. Use this\n"
"                    option with caution, it can generate huge trace files.\n"
" --unbuffered       Turn off output buffering. This causes every single line\n"
"                    emitted by sysdig to be flushed, which generates higher CPU\n"
"                    usage but is useful when piping sysdig's output into another\n"
"                    process or into a script.\n"
" -v, --verbose      Verbose output.\n"
"                    This flag will cause the full content of text and binary\n"
"                    buffers to be printed on screen, instead of being truncated\n"
"                    to 40 characters. Note that data buffers length is still\n"
"                    limited by the snaplen (refer to the -s flag documentation)\n"
"                    -v will also make sysdig print some summary information at\n"
"                    the end of the capture.\n"
" --version          Print version number.\n"
"\n");
}

double g_last_printed_progress_pct = 0;
char g_prg_line_buf[512] = "";

inline void clean_last_progress_line()
{
	uint32_t j;

	for(j = 0; j < strlen(g_prg_line_buf); j++)
	{
		g_prg_line_buf[j] = ' ';
	}
	g_prg_line_buf[j] = 0;
	
	fprintf(stderr, "\r%s", g_prg_line_buf);
}

inline void output_progress(sinsp* inspector, sinsp_evt* ev)
{
	if(ev == NULL || (ev->get_num() % 10000 == 0))
	{
		string ps;
		double progress_pct = inspector->get_read_progress_with_str(&ps);

		if(progress_pct - g_last_printed_progress_pct > 0.1)
		{
			clean_last_progress_line();
			if(ps == "")
			{
				snprintf(g_prg_line_buf, sizeof(g_prg_line_buf), "%.2lf", progress_pct);
			}
			else
			{
				snprintf(g_prg_line_buf, sizeof(g_prg_line_buf), "%s", ps.c_str());
			}

			fprintf(stderr, "\r%s", g_prg_line_buf);
			//fprintf(stderr, "%s\n", g_prg_line_buf);
			fflush(stderr);
			g_last_printed_progress_pct = progress_pct;
		}
	}
}

void handle_end_of_file(sinsp* inspector, bool print_progress, sinsp_evt_formatter_with_plugin_support* formatter = NULL)
{
	string line;

	// Notify the formatter that we are at the
	// end of the capture in case it needs to
	// write any terminating characters
	if(formatter != NULL && formatter->on_capture_end(&line))
	{
		cout << line << endl;
	}

	//
	// Reached the end of a trace file.
	// If we are reporting progress, this is 100%
	//
	if(print_progress)
	{
		clean_last_progress_line();
		if(inspector == NULL)
		{
			fprintf(stderr, "\r100.00\n");
		}
		else
		{
			output_progress(inspector, NULL);
			fprintf(stderr, "\n");
		}

		fflush(stderr);
	}
}

//
// Event processing loop
//
captureinfo do_inspect(sinsp* inspector,
	uint64_t cnt,
	bool do_flush,
	bool print_progress)
{
	captureinfo retval;
	int32_t res;
	sinsp_evt* ev;
	string line;

	//
	// Loop through the events
	//
	while(1)
	{
		if(retval.m_nevts == cnt || g_terminate)
		{
			//
			// End of capture, either because the user stopped it, or because
			// we reached the event count specified with -n.
			//
			break;
		}
		res = inspector->next(&ev);

		if(res == SCAP_TIMEOUT)
		{
			if(ev != NULL && ev->is_filtered_out())
			{
				//
				// The event has been dropped by the filtering system.
				//
				if(print_progress)
				{
					output_progress(inspector, ev);
				}
			}

			continue;
		}
		else if(res == SCAP_EOF)
		{
			break;
		}
		else if(res != SCAP_SUCCESS)
		{
			//
			// Event read error.
			// Notify the chisels that we're exiting, and then die with an error.
			//
			throw sinsp_exception(inspector->getlasterr().c_str());
		}

		retval.m_nevts++;

		if(print_progress)
		{
			output_progress(inspector, ev);
		}

		if(!inspector->is_debug_enabled() &&
			ev->get_category() & EC_INTERNAL)
		{
			continue;
		}

		if(do_flush)
		{
			cout << flush;
		}
	}

	return retval;
}

//
// ARGUMENT PARSING AND PROGRAM SETUP
//
sysdig_init_res sysdig_init(int argc, char **argv)
{
	sysdig_init_res res;
	sinsp* inspector = NULL;
	vector<string> infiles;
	int op;
	uint64_t cnt = -1;
	bool verbose = false;
	bool print_progress = false;
	double duration = 1;
	captureinfo cinfo;
	uint32_t snaplen = 0;
	int long_index = 0;
	int32_t n_filterargs = 0;
	bool unbuf_flag = false;
	bool bpf = false;
	string bpf_probe;
#ifdef HAS_CAPTURE
	string cri_socket_path;
#endif
	bool udig = false;
	string inputname;
	bool has_src_plugin = false;

	static struct option long_options[] =
	{
		{"bpf", optional_argument, 0, 'B' },
		{"help", no_argument, 0, 'h' },
		{"input", required_argument, 0, 'I' },
		{"numevents", required_argument, 0, 'n' },
		{"progress", required_argument, 0, 'P' },
		{"readfile", required_argument, 0, 'r' },
		{"snaplen", required_argument, 0, 's' },
		{"udig", required_argument, 0, 'u' },
		{"unbuffered", no_argument, 0, 0 },
		{"verbose", no_argument, 0, 'v' },
		{"version", no_argument, 0, 0 },
		{0, 0, 0, 0}
	};

	try
	{
		inspector = new sinsp();
		inspector->set_hostname_and_port_resolution_mode(false);

		sinsp_plugin::register_source_plugins(inspector, SYSDIG_INSTALLATION_DIR);

		//
		// Parse the args
		//
		while((op = getopt_long(argc, argv, "B::C:hI:n:Pr:s:uv", long_options, &long_index)) != -1)
		{
			switch(op)
			{
			case 'B':
			{
				bpf = true;
				if(optarg)
				{
					bpf_probe = optarg;
				}
				break;
			}
			case 'h':
				usage();
				delete inspector;
				return sysdig_init_res(EXIT_SUCCESS);
			case 'I':
				{
					inputname = optarg;
					if(inputname == "l")
					{
						sinsp_plugin::list_plugins(inspector);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}

					has_src_plugin = true;

					size_t cpos = inputname.find(':');
					string pgname;
					string pgpars;
					if(cpos != string::npos)
					{
						pgname = inputname.substr(0, cpos);
						pgpars = inputname.substr(cpos + 1);
						inspector->set_input_plugin(pgname);
						inspector->set_input_plugin_open_params(pgpars);
					}
					else
					{
						inspector->set_input_plugin(inputname);
					}

					g_plugin_input = true;
					//print_progress = true;
				}
				break;
			case 'n':
				try
				{
					cnt = sinsp_numparser::parseu64(optarg);
				}
				catch(...)
				{
					throw sinsp_exception("can't parse the -n argument, make sure it's a number");
				}

				if(cnt <= 0)
				{
					throw sinsp_exception(string("invalid event count ") + optarg);
					res.m_res = EXIT_FAILURE;
					goto exit;
				}
				break;
			case 'P':
				print_progress = true;
				break;
			case 'r':
				infiles.push_back(optarg);
				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 'u':
				udig = true;
				break;
			case 'v':
				verbose = true;
				break;
			case 0:
				{
					string optname = string(long_options[long_index].name);
					if (long_options[long_index].flag != 0) {
						break;
					}
					if (optname == "version") {
						printf("sysdig version %s\n", SYSDIG_VERSION);
						delete inspector;
						return sysdig_init_res(EXIT_SUCCESS);
					}
					else if (optname == "unbuffered") {
						unbuf_flag = true;
					}
				}
				break;
			// getopt_long : '?' for an ambiguous match or an extraneous parameter
			case '?':
				delete inspector;
				return sysdig_init_res(EXIT_FAILURE);
				break;
			default:
				break;
			}
		}

#ifdef HAS_CAPTURE
		if(!cri_socket_path.empty())
		{
			inspector->set_cri_socket_path(cri_socket_path);
		}
#endif

		if(!bpf)
		{
			const char *probe = scap_get_bpf_probe_from_env();
			if(probe)
			{
				bpf = true;
				bpf_probe = probe;
			}
		}

		if(bpf)
		{
			inspector->set_bpf_probe(bpf_probe);
		}

		//
		// If we are dumping events to file, enable progress printing so we can give
		// feedback to the user
		//
		if(infiles.size() != 0 || g_plugin_input == true)
		{
			print_progress = true;
		}

		string filter;

		//
		// the filter is at the end of the command line
		//
		if(optind + n_filterargs < argc)
		{
#ifdef HAS_FILTERING
			for(int32_t j = optind + n_filterargs; j < argc; j++)
			{
				filter += argv[j];
				if(j < argc - 1)
				{
					filter += " ";
				}
			}

#else
			fprintf(stderr, "filtering not compiled.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
#endif
		}

		if(signal(SIGINT, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGINT signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

		if(signal(SIGTERM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGTERM signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}

#ifndef _WIN32
		if(signal(SIGALRM, signal_callback) == SIG_ERR)
		{
			fprintf(stderr, "An error occurred while setting SIGALRM signal handler.\n");
			res.m_res = EXIT_FAILURE;
			goto exit;
		}
#endif

		for(uint32_t j = 0; j < infiles.size() || infiles.size() == 0; j++)
		{
#ifdef HAS_FILTERING
			if(filter.size())
			{
				inspector->set_filter(filter);
			}
#endif

			//
			// Launch the capture
			//
			if(infiles.size() != 0)
			{
				//
				// We have a file to open
				//
				inspector->open(infiles[j]);
			}
			else
			{
				if(j > 0)
				{
					break;
				}

				//
				// No file to open, this is a live capture
				//
#if defined(HAS_CAPTURE)
				bool open_success = true;

				if(print_progress && !g_plugin_input)
				{
					fprintf(stderr, "the -P flag cannot be used with live captures.\n");
					res.m_res = EXIT_FAILURE;
					goto exit;
				}

				if(udig)
				{
					inspector->open_udig();
				}
				else
				{
					if(has_src_plugin)
					{
						inspector->open("");
					}
					else
					{
						try
						{
							inspector->open("");
						}
						catch(const sinsp_exception& e)
						{
							open_success = false;
						}
					}
#ifndef _WIN32
					//
					// Starting the live capture failed, try to load the driver with
					// modprobe.
					//
					if(!open_success)
					{
						open_success = true;

						if(bpf)
						{
							if(bpf_probe.empty())
							{
								if(system("sysdig-probe-loader bpf"))
								{
									fprintf(stderr, "Unable to load the BPF probe\n");
								}
							}
						}
						else
						{
							if(system("modprobe " PROBE_NAME " > /dev/null 2> /dev/null"))
							{
								fprintf(stderr, "Unable to load the driver\n");
							}
						}

						inspector->open("");
					}
#endif // _WIN32
				}
#else // HAS_CAPTURE
				//
				// Starting live capture
				// If this fails on Windows and OSX, don't try with any driver
				//
				inspector->open("");
#endif // HAS_CAPTURE

				//
				// Enable gathering the CPU from the kernel module
				//
				if(!udig)
				{
					inspector->set_get_procs_cpu_from_driver(true);
				}
			}

			//
			// If required, set the snaplen
			//
			if(snaplen != 0)
			{
				inspector->set_snaplen(snaplen);
			}

			duration = ((double)clock()) / CLOCKS_PER_SEC;

#ifndef MINIMAL_BUILD
			//
			// run k8s, if required
			//
			if(k8s_api)
			{
				if(!k8s_api_cert)
				{
					if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
					{
						k8s_api_cert = new string(k8s_cert_env);
					}
				}
				inspector->init_k8s_client(k8s_api, k8s_api_cert, verbose);
				k8s_api = 0;
				k8s_api_cert = 0;
			}
			else if(char* k8s_api_env = getenv("SYSDIG_K8S_API"))
			{
				if(k8s_api_env != NULL)
				{
					if(!k8s_api_cert)
					{
						if(char* k8s_cert_env = getenv("SYSDIG_K8S_API_CERT"))
						{
							k8s_api_cert = new string(k8s_cert_env);
						}
					}
					k8s_api = new string(k8s_api_env);
					inspector->init_k8s_client(k8s_api, k8s_api_cert, verbose);
				}
				else
				{
					delete k8s_api;
					delete k8s_api_cert;
				}
				k8s_api = 0;
				k8s_api_cert = 0;
			}

			//
			// run mesos, if required
			//
			if(mesos_api)
			{
				inspector->init_mesos_client(mesos_api, verbose);
			}
			else if(char* mesos_api_env = getenv("SYSDIG_MESOS_API"))
			{
				if(mesos_api_env != NULL)
				{
					mesos_api = new string(mesos_api_env);
					inspector->init_mesos_client(mesos_api, verbose);
				}
			}
			delete mesos_api;
			mesos_api = 0;
#endif
			cinfo = do_inspect(inspector,
				cnt,
				unbuf_flag,
				print_progress);

			duration = ((double)clock()) / CLOCKS_PER_SEC - duration;

			scap_stats cstats;
			inspector->get_capture_stats(&cstats);

			if(verbose)
			{
				fprintf(stderr, "Driver Events:%" PRIu64 "\nDriver Drops:%" PRIu64 "\nSuppressed by Comm:%" PRIu64 "\n",
					cstats.n_evts,
					cstats.n_drops,
					cstats.n_suppressed);

				fprintf(stderr, "Elapsed time: %.3lf, Captured Events: %" PRIu64 ", %.2lf eps\n",
					duration,
					cinfo.m_nevts,
					(double)cinfo.m_nevts / duration);
			}

			//
			// Done. Close the capture.
			//
			inspector->close();
		}
	}
	catch(const sinsp_capture_interrupt_exception&)
	{
		handle_end_of_file(NULL, print_progress);
	}
	catch(const scap_open_exception& e)
	{
		cerr << e.what() << endl;
		handle_end_of_file(NULL, print_progress);
		res.m_res = e.scap_rc();
	}
	catch(const sinsp_exception& e)
	{
		cerr << e.what() << endl;
		handle_end_of_file(NULL, print_progress);
		res.m_res = EXIT_FAILURE;
	}
	catch (const std::runtime_error& e)
	{
		cerr << e.what() << endl;
		handle_end_of_file(NULL, print_progress);
		res.m_res = EXIT_FAILURE;
	}
	catch(...)
	{
		handle_end_of_file(NULL, print_progress);
		res.m_res = EXIT_FAILURE;
	}

exit:

	if(inspector)
	{
		delete inspector;
	}

	return res;
}

//
// MAIN
//
int main(int argc, char **argv)
{
	sysdig_init_res res;

	res = sysdig_init(argc, argv);

#ifdef _WIN32
	_CrtDumpMemoryLeaks();
#endif

	return res.m_res;
}
