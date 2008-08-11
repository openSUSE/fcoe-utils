/*
 -- LICENSE
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>

#define SYSFS_MOUNT	"/sys"
#define SYSFS_NET	SYSFS_MOUNT "/class/net"
#define SYSFS_FCHOST	SYSFS_MOUNT "/class/fc_host"
#define SYSFS_FCOE	SYSFS_MOUNT "/module/fcoe"
#define FCOE_CREATE	SYSFS_FCOE "/create"
#define FCOE_DESTROY	SYSFS_FCOE "/destroy"

static struct option fcoeadm_opts[] = {
    {"create", 1, 0, 'c'},
    {"destroy", 1, 0, 'd'},
    {"query", 1, 0, 'q'},
    {"help", 0, 0, 'h'},
    {0, 0, 0, 0}
};


void fcoeadm_help(char *name)
{
	fprintf(stderr, "Usage: %s\n"
		"\t [-c|--create] ifname\n"
		"\t [-d|--destroy] ifname\n"
		"\t [-q|--query] ifname\n"
		"\t [-h|--help]\n",
		name);
}

/*
 * open and close to check if dir exists
 */
int fcoeadm_checkdir(char *dir)
{
	DIR *d = NULL;

	if (!dir)
		return -EINVAL;
	/* check if we have sysfs */
	d = opendir(dir);
	if (!d)
		return -EINVAL;
	closedir(d);
	return 0;
}
/*
 * TODO - check this ifname before performing any action
 */
int fcoeadm_check(char *ifname)
{
	char path[256];
	/* check if we have sysfs */
	if (fcoeadm_checkdir(SYSFS_MOUNT)) {
		fprintf(stderr, "Sysfs mount point %s not found!\n", SYSFS_MOUNT);
		return -EINVAL;
	}
	/* check fcoe module */
	if (fcoeadm_checkdir(SYSFS_FCOE)) {
		fprintf(stderr, "Please make sure FCoE driver module is loaded!\n");
		return -EINVAL;
	}
	/* check target interface */
	if (!ifname) {
		fprintf(stderr, "Invalid interface name!\n");
		return -EINVAL;
	}
	sprintf(path, "%s/%s", SYSFS_NET, ifname);
	if (fcoeadm_checkdir(path)) {
		fprintf(stderr, "Interface %s not found!\n", ifname);
		return -EINVAL;
	}

	return 0;
}

/*
 * TODO - for now, this just writes to path
 */
int fcoeadm_action(char *path, char *s)
{
	FILE *fp = NULL;

	if (!path) 
		return -EINVAL;

	if (!s)
		return -EINVAL;

	fp = fopen(path, "w");
	if (!fp) {
		fprintf(stderr, "Failed to open %s\n", path);
		return -ENOENT;
	}
	if( EOF == fputs(s, fp))
		fprintf(stderr, "Failed to write %s to %s\n", s, path);

	fclose(fp);
	
	return 0;
}

/*
 * 
 */
char *fcoeadm_read(const char *path)
{
	FILE *fp;
	char *buf;
	int size = 512;

	if (!path)
		return NULL;

	buf = malloc(size);
	if (!buf)
		return NULL;
	memset(buf, 0, size);

	fp = fopen(path, "r");
	if (fp) {
		if (fgets(buf, size, fp)) {
			fclose(fp);
			return buf;
		}
	}
	fclose(fp);
	free(buf);
	return NULL;
}

/*
 *
 */
int fcoeadm_query_attr(const char *fchost, const char *attr)
{
	char *buf;
	char path[512];

	sprintf(path, "%s/%s/%s", SYSFS_FCHOST, fchost, attr);
	buf = fcoeadm_read(path);
	if (buf) {
		fprintf(stderr, "%s:\t%s", attr, buf);
		free(buf);
	}
	return 0;
}

/*
 * TODO - query sysfs for this fcoe instance
 */
int fcoeadm_query_fchost(const char *ifname, const char *fchost)
{
	if (!fchost)
		return -EINVAL;
	/* TODO - use filterfunc later */
	fprintf(stderr, "Query attributes for %s on %s:\n", ifname, fchost);
	fcoeadm_query_attr(fchost, "fabric_name");
	fcoeadm_query_attr(fchost, "node_name");
	fcoeadm_query_attr(fchost, "port_name");
	fcoeadm_query_attr(fchost, "port_type");
	fcoeadm_query_attr(fchost, "symbolic_name");
	fcoeadm_query_attr(fchost, "active_fc4s");
/*
active_fc4s  fabric_name  node_name  port_name  power  statistics  supported_classes  symbolic_name    uevent
device       issue_lip    port_id    port_type  speed  subsystem   supported_fc4s     tgtid_bind_type
*/
	return 0;
}	


int fcoeadm_check_fchost(const char *ifname, const char *dname)
{
	char *buf;
	char path[512];
	if (!ifname)
		return -EINVAL;

	if (!dname)
		return -EINVAL;

	if (dname[0] == '.')
		return -EINVAL;

	sprintf(path, "%s/%s/symbolic_name", SYSFS_FCHOST, dname);
	buf = fcoeadm_read(path);
	if (!buf)
		return -EINVAL;

	if (!strstr(buf, ifname)) {
		free(buf);
		return -EINVAL;
	}
	free(buf);
	return 0;
}
/*
 * TODO -  FCoE dump the instance
 */
int fcoeadm_query(char *ifname) 
{
	int n;
	int found = 0;
	char fchost[64];
	struct dirent **namelist;

	if (!ifname)
		return -EINVAL;

	memset(fchost, 0, sizeof(fchost));
	n = scandir(SYSFS_FCHOST, &namelist, 0, alphasort);
	if (n > 0) {
		while (n--) {
			/* check symboli name */
			if (!fcoeadm_check_fchost(ifname, namelist[n]->d_name)) {
				strncpy(fchost, namelist[n]->d_name, sizeof(fchost));
				found = 1;
			}
			free(namelist[n]);
		}
	}
	free(namelist);
	/* check */
	if (!found) {
		fprintf(stderr, "FCoE instance not found for %s\n", ifname);
		return -EINVAL;
	}
	return fcoeadm_query_fchost(ifname, fchost);			
}
/* 
 * create FCoE instance for this ifname
 */
int fcoeadm_create(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr, "Failed to create FCoE instance on %s!\n", ifname);
		return -EINVAL;
	}
	fprintf(stderr, "Creating FCoE instance for %s\n", ifname);
	return fcoeadm_action(FCOE_CREATE, ifname);
}

/*
 * remove FCoE instance for this ifname
 */
int fcoeadm_destroy(char *ifname)
{
	if (fcoeadm_check(ifname)) {
		fprintf(stderr, "Failed to destroy FCoE instance on %s!\n", ifname);
		return -EINVAL;
	}
	fprintf(stderr, "Destroying FCoE instance for %s\n", ifname);
	return fcoeadm_action(FCOE_DESTROY, ifname);
}


int main(int argc, char *argv[])
{
	int opt;
	int rc = -1;

	if (argc <= 1) {
		fcoeadm_help(argv[0]);
		exit(-EINVAL);
	}

	while ((opt = getopt_long(argc, argv, "c:d:q:h", fcoeadm_opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			rc = fcoeadm_create(optarg);
			goto done;
		case 'd':
			rc = fcoeadm_destroy(optarg);
			goto done;
		case 'q':
			rc = fcoeadm_query(optarg);
			goto done;
		case 'h':
		default:
			fcoeadm_help(argv[0]);
			exit(-EINVAL);
		}
	}
done:
	printf( (rc == 0) ? "Succcess!\n" : "Failed!\n");
	return 0;
}
