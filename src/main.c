/* chdsweep: command line */
#include "chdsweep.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(FILE *f)
{
    fputs(
        "chdsweep " CHD_VERSION " - cardholder data discovery for servers\n"
        "\n"
        "  chdsweep scan [options] [path ...]   search for card numbers, write a run file\n"
        "  chdsweep report [options] RUN ...    merge run files into one report (md, html, csv)\n"
        "  chdsweep bin-update FILE             make a dated BIN table from a downloaded data set\n"
        "  chdsweep check                       list the optional libraries, found or missing\n"
        "  chdsweep version\n"
        "\n"
        "Without a path, in the config file or on the command line, scan searches /root,\n"
        "/home, the current logs in /var/log and the system journal of the last 35 days.\n"
        "\n"
        "scan options (each overrides the config file):\n"
        "  -c FILE            config file (default /etc/chdsweep.conf, if present)\n"
        "  -o FILE            run file to write (default <output_dir>/chdsweep-<host>-<time>.jsonl)\n"
        "  -j N               worker threads (default 1; more read faster and load the disk more)\n"
        "  -q                 quiet: no summary at the end (cron)\n"
        "  -p, --progress     on a terminal, show what each worker is doing (off by default)\n"
        "  -x PATTERN         exclude a folder or glob; may be repeated. '*.gz' applies\n"
        "                     everywhere, '/var/log/*.gz' under that folder only\n"
        "  -s KEY=VALUE       any config setting, e.g. -s max_depth=2\n"
        "  --no-lock          do not take the lock file\n"
        "\n"
        "exit codes: 0 full coverage, 1 partial coverage, 2 failed, 3 another run holds the lock.\n"
        "Whether cards were found is in the run file, not in the exit code.\n",
        f);
}

static int bad(const char *msg, const char *arg)
{
    fprintf(stderr, "chdsweep: %s%s\n", msg, arg ? arg : "");
    return EXIT_FAILED;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(stderr); return EXIT_FAILED; }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version")) {
        puts("chdsweep " CHD_VERSION "\n"
             "Copyright (c) 2026 D.J.S. van den Akker. MIT License.\n"
             "Inspired by ccsrch (Mike Beekey, Adam Caudill) and PANhunt (Dionach; the zbalkan fork).\n"
             "Built-in BIN table: " BIN_ATTRIBUTION);
        return 0;
    }
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) { usage(stdout); return 0; }
    if (!strcmp(cmd, "check")) return cmd_check();
    if (!strcmp(cmd, "report")) return cmd_report(argc, argv);
    if (!strcmp(cmd, "bin-update")) return cmd_bin_update(argc, argv);
    if (strcmp(cmd, "scan")) { usage(stderr); return bad("unknown command ", cmd); }

    static struct config cfg;   /* static: lives as long as the process */
    static struct strlist cli_paths;
    char err[600];
    config_defaults(&cfg);

    /* Config file first, then the command line on top of it. */
    const char *config_path = NULL;
    for (int i = 2; i < argc - 1; i++)
        if (!strcmp(argv[i], "-c")) config_path = argv[i + 1];
    if (!config_path && access("/etc/chdsweep.conf", R_OK) == 0) config_path = "/etc/chdsweep.conf";
    if (config_path && config_load(&cfg, config_path, err, sizeof err)) return bad("config: ", err);

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        const char *key = NULL;
        if (!strcmp(a, "-c")) { if (!v) return bad("missing value for ", a); i++; continue; }
        else if (!strcmp(a, "-q")) { cfg.quiet = 1; continue; }
        else if (!strcmp(a, "-p") || !strcmp(a, "--progress")) { cfg.progress = 1; continue; }
        else if (!strcmp(a, "--no-lock")) { free(cfg.lock_file); cfg.lock_file = xstrdup(""); continue; }
        else if (!strcmp(a, "-o")) key = "output_file";
        else if (!strcmp(a, "-j")) key = "threads";
        else if (!strcmp(a, "-x")) key = "exclude";
        else if (!strcmp(a, "-s")) {
            if (!v || !strchr(v, '=')) return bad("-s needs KEY=VALUE", NULL);
            char *kv = xstrdup(v), *eq = strchr(kv, '=');
            *eq = 0;
            if (config_set(&cfg, kv, eq + 1, err, sizeof err)) return bad("", err);
            free(kv);
            i++;
            continue;
        } else if (a[0] == '-' && a[1]) return bad("unknown option ", a);
        else { sl_add(&cli_paths, a); continue; }
        if (!v) return bad("missing value for ", a);
        if (config_set(&cfg, key, v, err, sizeof err)) return bad("", err);
        i++;
    }
    if (cli_paths.n) {   /* paths on the command line replace the config's */
        for (int i = 0; i < cfg.paths.n; i++) free(cfg.paths.v[i]);
        free(cfg.paths.v);
        cfg.paths = cli_paths;
    }

    return cmd_scan(&cfg, config_path);
}
