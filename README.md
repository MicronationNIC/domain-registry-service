# Getting started
1. Install and prepare PostgreSQL.
2. Install and prepare CoreDNS.
3. Download the repository (use `git clone git@github.com:MicronationNIC/domain-registrar-site.git`).
4. Globally install pm2 using `npm install pm2 -g`.
5. Prepare the configuration.
6. Configure the registry's registrar configurations.
7. Start the service by using `pm2 start server.ts` in the directory containing the `server.ts` file for this repository.

# Preparing the configurations
1. Create a configuration directory. The service should have read and execute access to this directory (write access is not needed here) and at least execute access to any parent directories to this directory.
2. Directly in the configuration directory, create a directory named `dns`. This directory contains the configuration relating to the interaction of this service with the DNS service. This service should have rwx (0o7) permission to this directory.
3. Inside the `dns` directory, create a new file called `dns_ct`. You can include any date prior to the current date (YYYYMMDD format, with leading zeroes if applicable), followed by one space, followed by any number on the interval of [0, 99] (the second number does not need a trailing zero). The service should have at least rw- (0o6) to this file.
4. Inside the `dns` directory, create a new yaml file called `dns.yaml`. This file should contain a `zones-conf` with the absolute path to a file which must be imported by the Corefile and to which the service has at least rw- (0o6) permissions to that file and at least --x (0o1) permissions to all parent directories. This file should also contain a `zones-dir` with the absolute path to a directory of zones which the service must have at least -wx (0o3) permissions to that directory and at least --x (0o1) permissions to all parent directories.
5. Directly in the configuration directory, create a directory named `registrars`. The service should have at least r-x (0o5) permissions to this directory.
6. Inside the `registrars` directory, place a file named `registrardb.yaml`. The service should have at least r-- (0o4) permissions to this file. The keys of this file should be the IDs of the registrars, while the values should be the path (relative to the configuration directory, without a leading /) of that registrar's configuration file for this registry. See the section on adding registrars for more information about the `registrardb.yaml` file and the registrar configuration files.
7. Directly in the configuration directory, create a directory named `ssl`. The service should have at least r-x (0o5) permissions to this directory.
8. Inside of the `ssl` directory, put your SSL private key under `privkey.pem`. The service should have at least r-- (0o4) permissionss to this file.
9. Inside of the `ssl` directory, put your SSL public key chain under `fullchain.pem`. This service should have at least r-- (0o4) permissions to this file.
10. Directly inside of the configuration directory, add a file called `tos.md`. This service should have at least r-- (0o4) permissions to this file. Inside of this file, write out your Terms of Service.
11. Directly inside of the directory where your `server.ts` file is for this service, create a new file called `.env` for your environment variables. The service should have at least r-- (0o4) permissions to this file.
12. Add an environment variable for `MAINDIR` to the absolute path of your configuration directory, including a forwardslash at the end.
13. Optionally, add an environment variable for an administrator password hashed with SHA256 at `ADMINPASSWORD`. This feature is not yet implemented.
14. Optionally, add an environment variable for the port of this service at `PORT`. By default, the port is 9999.
15. Add an environment variable for `POSTGRES_USER`. This variable should be the user of PostgreSQL that is to be used by the service.
16. Add an environment varibale for `POSTGRES_HOST`. This variable should be the IP address of PostgreSQL that is to be used by the service.
17. Add an environment variable for `POSTGRES_DB`. This variable should be the name of the database that is used for this service. If unset, it will use `domain_registry_db`.
18. Add an environment variable for `POSTGRES_PASSWD`. This variable should be the password of PostgreSQL that is to be used by the service.
19. Add an environment variable for `POSTGRES_PORT`. This variable should be the port of PostgreSQL that is to be used by the service.
20. Add an environment variable for `COREDNS_GROUP`. This variable should be the group ID of CoreDNS. It should be a number.
21. Add an environment variable for `COREDNS_USER`. This variable should be the user ID of CoreDNS. It should be a number.
22. Add an environment variable for `SOURCE_CODE`. This variable should be the URL that takes the user to the source code of the service. If you are using the original software, set it to https://github.com/MicronationNIC/domain-registry-service. Otherwise, set it to whereever users can access the source code. If left blank, users will get a 404 error when trying to GET /source-code for this service.

# Configurations of registrars
The registry service must have at least r-- (0o4) permissions to this file and at least --x (0o1) permissions to the parent directories. The registrardb.yaml file should have an entry for the ID of this registrar to the corresponding configuration file for that registrar's configuration file's file path relative to the registry's configuration directory which should not start with a forwardslash. It is recommended that each registrar gets a directory for configuration in the `registrars` directory of the configuraiton directory. The following are the various configurations that are available for each registrar:

## registrar-name
This is the name of the registrar. It is not the same as the registrar ID. The registrar ID is what is used for most in the registry service. The registrar name does not currently serve a function. It can be any string value.

## tld-authority
This is what the registrar can register. Remember that this only applies to registrations and (when implemented) transfers. Domain names that are added manually can still be managed and renewed through this method. It is an extremely important section. It is a list of more sets of key-value pairs. Here they are:

### tld
This is the TLD. It is based on the entire domain name that is intended to be registered, but without the first part. For example, the TLD when someone tries to register `everyoneshouldbehealthy.fdc.po` is `fdc.po`. In this example though, it is important to exclude `fdc.po` from the authority with the tld value set to `po` (if there is one). Otherwise, someone could register the `fdc.po` domain (which comes with subdomains). See the information about `exclude` here for how to do that. You should also remember that some domain names should be written using punycode. [This website](https://www.punycoder.com/) (we are not affiliated with that website) helps to convert domain names into punycode when needed. This value should be a string.

### exclude
This is the excluded domain names. These domains cannot be registered, even if the registrar otherwise has authority for that TLD. These can be used for reserving domain names but also for when there is a TLD that has sub-TLDs. For example, `gav.po`, `fdc.po`, and `ras.po` would be excluded from the authority of `po`.

### qty-limit
This is not yet implemented.

### domains-expire-after
This is how long it takes for a domain to expire after the initial registration. It should be in milliseconds. It should be a number. For example, for it to be 365,5 + 7 days, you would set this value to 32162400000.

### domain-name-renewal
This is how many milliseconds after the registration of the domain name that the domain name is to be renewed. Upon renewal, the expiration date and the renewal date increase by this amount of time. The renewal date is the earliest date at which the domain name may be renewed.

## public-key
Note: this is not part of `tld-authority`. This is the configuration for authenticating the registrar. It consists of the following key-value pairs:

### filename
This is the file of the public key. The file path is relative to the configuration directory for the registry service. The registry service must have at least r-- (0o4) permissions to the file specified here and at least --x (0o1) permissions to any parent directory thereof. The file path should not include a forwardslash. The file should be the raw public key encoded in base 64. The registrar site comes with a script to generate such a keypair. The registry should only have the public key.

### expiry
This is not yet implemented. When it does get implemented, it would be the number of milliseconds since epoch time at which the key would no longer be valid. It can safely be omitted. It would be a number.

### type
At this time, only `ML-DSA-87` is supported. This value is not yet checked.

## website
Note: this is not part of `public-key`. This is the list of websites through which the registrar can be accessed. It should be a list of strings.

## qty-limit
This is not yet implemented.

# Setting up PostgreSQL
```sql
CREATE TABLE public.domains
(
	domain_name TEXT UNIQUE NOT NULL,
    domain_name_original TEXT UNIQUE NOT NULL,
	tld TEXT NOT NULL,
	time_registered TIMESTAMPTZ DEFAULT NOW(),
	last_updated TIMESTAMPTZ DEFAULT NOW(),
	expiration TIMESTAMPTZ,
	registrar_id TEXT NOT NULL,
    renewal_time TIMESTAMPTZ
);
```