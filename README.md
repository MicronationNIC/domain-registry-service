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