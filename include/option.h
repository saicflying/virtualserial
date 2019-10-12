#ifndef __SD_OPTION_H__
#define __SD_OPTION_H__

#include <stdbool.h>
#include <getopt.h>

struct soe_option {
	int ch;
	const char *name;
	bool has_arg;
	const char *desc;
	const char *help;
};

struct option_parser {
	const char *option;
	int (*parser)(const char *);
};

char *build_short_options(const struct soe_option *opts);
struct option *build_long_options(const struct soe_option *opts);
const char *option_get_help(const struct soe_option *, int);
int option_parse(char *arg, const char *delim, struct option_parser *parsers);

#define soe_for_each_option(opt, opts)		\
	for (opt = (opts); opt->name; opt++)

#endif /* __SD_OPTION_H__ */
