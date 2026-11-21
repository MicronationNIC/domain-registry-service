require('dotenv').config();
const express = require('express');
const app = express();
const fs = require('fs');
const https = require('https');
const yaml = require('js-yaml');
const { Client } = require('pg');
const crypto = require('crypto');
const { domainToASCII } = require('node:url');
const dnszone = require('@nictool/dns-zone');
const path = require('node:path');
const maindir = process.env.MAINDIR || '/etc/registryservice';
const port = process.env.PORT || 443;
const timegrace = parseInt(process.env.TIMEGRACE) || 5000; // In milliseconds

let critical_processes_running = 0;

var options = {
    key: fs.readFileSync(maindir + 'ssl/privkey.pem', 'utf8'),
    cert: fs.readFileSync(maindir + 'ssl/fullchain.pem', 'utf8')
}

function setNumStrLen(numstr, len) {
    numstr = numstr.toString();
    //console.log(numstr, numstr.length);
    if (!len) len = 2;
    if (numstr.length >= len) return numstr;
    while (numstr.length < len) {
        numstr = '0' + numstr;
        //console.log(numstr, numstr.length);
    }
    return numstr;
}

function getTimestamp() {
    let now = new Date()
    return `${now.getUTCFullYear()}-${setNumStrLen(now.getUTCMonth())}-${setNumStrLen(now.getUTCDate())} ${setNumStrLen(now.getUTCHours())}:${setNumStrLen(now.getUTCMinutes())}:${setNumStrLen(now.getUTCSeconds())}.${setNumStrLen(now.getUTCMilliseconds(), 3)} UTC`;
}

/**
 * WARNING: This function does not query postgres to check if the registrar has authority to update an existing domain. This is not for use in amending existing domain name records.
 * @param {string} registrar - The ID of the registrar to check its authority
 * @param {string} domain_name - The full domain name which is intended to be registered
 */
function checkRegistrarDomainAuthorityForRegistration(registrar, domain_name) {
    if (registrar == undefined) return false;
    if (!(registrar in registrar_cfgs)) return false;
    if (!('tld-authority' in registrar_cfgs[registrar])) return false;
    if (domain_name.endsWith('.')) return false;
    
    let tld = domain_name.includes('.') ? domain_name.substring(domain_name.indexOf('.') + 1) : '.';
    
    for (let authority of registrar_cfgs[registrar]['tld-authority']) {
        if (authority['tld'] === tld) {
            if (!authority['exclude'].includes(domain_name)) {
                return true;
            }
        }
    }
    
    return false;
}

const subtle = crypto.webcrypto.subtle;
const encoder = new TextEncoder();
async function check_ml_dsa_87_signature(signature_b64, data, key_b64) {
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    
    try {
        const public_key = Buffer.from(key_b64, 'base64');
        const signature = Buffer.from(signature_b64, 'base64');
        
        if (public_key.length !== 2592 || signature.length !== 4627) {
            return false;
        }
        
        return await ml_dsa87.verify(
            signature,
            encoder.encode(data),
            public_key
        );
    } catch {
        return false;
    }
}

function validateDomain(input) {
    if (typeof input !== 'string') return null;

    // Remove surrounding whitespace.
    let domain = input.trim();

    // Reject empty names and excessively long input.
    if (!domain || domain.length > 1024) return null;

    // Do not accept URLs, paths, ports, wildcards or whitespace.
    if (/[\s/:?#@*\\]/u.test(domain)) return null;

    // Remove one optional trailing dot (FQDN notation).
    if (domain.endsWith('.')) {
        domain = domain.slice(0, -1);
    }

    // Convert Unicode to ASCII/Punycode.
    const ascii = domainToASCII(domain).toLowerCase();

    if (!ascii || ascii.length > 253) return null;

    const labels = ascii.split('.');

    // DNS labels must be 1–63 octets.
    for (const label of labels) {
        if (
            label.length < 1 ||
            label.length > 63 ||
            !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
        ) {
            return null;
        }
    }

    return ascii;
}

async function rfc1035ToJson(filename, default_origin) {
    let domain_records_file_text = fs.readFileSync(filename).toString();
    let domain_records_full = await dnszone.bind.parseZoneFile(domain_records_file_text);
    
    let ttl_default = undefined;
    let records = [];
    let origin = default_origin;
    let soa = undefined;
    
    for (let record of domain_records_full) {
        if ('$TTL' in record) {
            ttl_default = record['$TTL'];
            continue;
        }
        
        if ('$ORIGIN' in record) {
            origin = record['$ORIGIN'];
            continue;
        }
        
        if (record['type'] === undefined) continue;
        if (record['type'] === 'SOA') {
            soa = record;
            continue;
        }
        
        if (record['owner'] === undefined || record['class'] === undefined) continue;
        
        let data = undefined;
        switch (record['type']) {
            case 'A':
                data = record['address'];
                break;
            case 'TXT':
                data = record['data'];
                break;
            default:
                break;
        }
        
        if (data === undefined) continue;
        
        let name = record['owner'].slice(0, -origin.length);
        if (name === '') name = '@';
        
        records.push({
            'type': record['type'],
            'name': name,
            'ttl': record['ttl'],
            'data': data
        });
    }
    
    return {
        ttl_default,
        records,
        origin,
        soa
    }
}

function updateFileAtomic(filename, text, returnIfNotExists) {
    if (returnIfNotExists && !fs.existsSync(filename)) {
        return false;
    }
    if (!fs.existsSync(path.dirname(filename))) {
        return false;
    }
    let filestat = fs.existsSync(filename) ? fs.statSync(filename) : fs.statSync(path.dirname(filename));
    fs.writeFileSync(filename + '.tmp', text);
    fs.chmodSync(filename + '.tmp', filestat.mode);
    fs.chownSync(filename + '.tmp', filestat.uid, filestat.gid);
    fs.renameSync(filename + '.tmp', filename);
    return true;
}

function getNewZoneSerial() {
    let date = new Date();
    let dns_ct = fs.readFileSync('dns_ct');
    let cdate = `${setNumStrLen(date.getUTCFullYear(),4)}${setNumStrLen(date.getUTCMonth())}${setNumStrLen(date.getUTCDate())}`;
    let serialsplit = dns_ct.split(' ',1)
    let ctdate = serialsplit[0];
    let ctval = serialsplit[1];
    if (parseInt(cdate) > parseInt(ctdate)) {
        ctdate = cdate;
        ctval = 0;
    } else {
        ctval = parseInt(ctval) + 1;
    }
    fs.writeFileSync(maindir + 'cfg/dns/dns_ct', ctdate + ' ' + ctval);
    return cdate + ctval;
}

function prepareTxtRecord(text) {
    if (typeof text !== String) return '';
    text = ''; // REMEMBER TO REMOVE THIS LINE, THIS LINE BREAKS THE CODE IN EXCHANGE FOR FIXING TYPES
}

const A_DATA_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])$/;
const AAAA_DATA_REGEX = /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9]))$/;
function updateDomainFile(domain_name, json) {
    let filename = dns_cfg['zones-dir'] + '/db.' + domain_name;
    let text = `$TTL ${json['ttl_default']}\n$ORIGIN ${json['origin']}\n\n`;
    text += `@ IN SOA ns1.sandwich.po. hostmaster.sandwich.po. ${getNewZoneSerial()} 3600 600 1209600 300\n`
    
    for (record of json['records']) {
        if (!['A', 'AAAA', 'TXT'].includes(record['type'])) continue;
        text += '\n' + record['name'] + ' ';
        if (record['ttl'] !== undefined) text += record['ttl'] + ' ';
        text += ' IN ' + record['type'] + ' ';
        switch (record['type']) {
            case 'A':
                if (A_DATA_REGEX.test(record['data'])) {
                    text += record['data'];
                    break;
                }
                return 'INVALID_DATA';
            case 'AAAA':
                if (AAAA_DATA_REGEX.test(record['data'])) {
                    text += record['data'];
                    break;
                }
                return 'INVALID_DATA';
            case 'TXT':
                
        }
    }
    return updateFileAtomic(filename, text, true) ? 'OK' : 'ATOMIC_WRITE_FAIL';
}
rfc1035ToJson('./cfg/dns/zones/db.pizza.po').then((v) => console.log(v));

function updateRfc1035Record(filename, idToUpdate, newRecord) {
    let current = rfc1035ToJson(filename);
}

// Load postgres
const client = new Client({
    user: process.env.POSTGRES_USER,
    host: process.env.POSTGRES_HOST || 'localhost',
    database: process.env.POSTGRES_DB || 'domain_registry_db',
    password: process.env.POSTGRES_PASSWD,
    port: process.env.POSTGRES_PORT || 5432,
});
client.connect();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const registrars = yaml.load(fs.readFileSync(maindir + '/registrars/registrardb.yaml'));
const registrar_cfgs = {}
for (let registrar of Object.keys(registrars)) {
    let cfgfile = registrars[registrar].startsWith('/') ? registrars[registrar] : maindir + '/' + registrars[registrar];
    if (!fs.existsSync(cfgfile)) {
        console.error(`[ERROR @ ${getTimestamp()}] Configuration file for ${registrar} does not exist at ${cfgfile}.`);
        registrars[registrar] = undefined;
        continue;
    }
    registrar_cfgs[registrar] = yaml.load(fs.readFileSync(cfgfile).toString());
}

app.get('/check-domain-availability', async (req, res) => {
    let registrar_id = req.query.registrar_id;
    let domain_name = validateDomain(req.query.domain_name);
    // Validate domain_name field
    if (domain_name == null) {
        return res.status(422).json({
            'success': false,
            'status_text': "DOMAIN_NAME_INVALID",
            'can_register': false
        });
    }
    
    // See if the domain name is already registered
    let qres = await client.query('SELECT domain_name FROM public.domains WHERE domain_name = $1', [domain_name]);
    if (qres.rowCount > 0) {
        return res.status(200).json({
            'success': true,
            'status_text': "DOMAIN_ALREADY_REGISTERED",
            'can_register': false
        });
    }
    
    // See if the domain name is eligible for registration by that registrar
    if (!checkRegistrarDomainAuthorityForRegistration(registrar_id, domain_name)) {
        return res.status(200).json({
            'success': true,
            'status_text': "DOMAIN_NOT_REGISTERED",
            'can_register': false
        });
    }
    
    res.status(200).json({
        'success': true,
        'status_text': "DOMAIN_NOT_REGISTERED",
        'can_register': true
    });
});

const dns_cfg = yaml.load(fs.readFileSync(maindir + '/dns/dns.yaml'));
app.post('/register-domain', async (req, res) => {
    let date = new Date();
    let timenow = date.getTime();
    let authtoken = req.body.authtoken;
    let timeauth = req.body.timeauth;
    let registrar_id = req.body.registrar_id;
    let domain_name_original = req.body.domain_name;
    let domain_name = domain_name_original;
    while (domain_name.endsWith('.')) {
        domain_name = domain_name.slice(0,-1);
    }
    while (domain_name.startsWith('.')) {
        domain_name = domain_name.slice(1);
    }
    
    // Authenticate registrar
    if (timeauth + timegrace < timenow || timeauth > timenow + timegrace) {
        res.status(401).json({
            'success': false,
            'status_text': 'AUTHENTICATION_TOKEN_TOO_OLD',
            'status_code': 401,
            'try_again': true,
            'domain_name': domain_name
        });
        return;
    }
    let public_key_location = registrar_cfgs[registrar_id]['public-key']['filename'];
    public_key_location = public_key_location.startsWith('/') ? public_key_location : maindir + '/' + public_key_location;
    if (!fs.existsSync(public_key_location)) {
        res.status(401).json({
            'success': false,
            'status_text': 'REGISTRAR_AUTHENTICATION_PUBLIC_KEY_NOT_FOUND',
            'status_code': 401,
            'try_again': false,
            'domain_name': domain_name
        });
        console.error(`[ERROR @ ${getTimestamp()}] Failed to find public key for registrar ${registrar_id}.`);
        return;
    }
    let registrar_public_key = fs.readFileSync(public_key_location).toString();
    let authtokendata = {
        timeauth,
        registrar_id,
        'domain_name': domain_name_original,
        'intent': 'register_domain'
    }
    
    if (!(await check_ml_dsa_87_signature(authtoken, JSON.stringify(authtokendata), registrar_public_key))) {
        return res.status(401).json({
            'success': false,
            'status_text': 'INVALID_CREDENTIALS',
            'status_code': 401,
            'try_again': false,
            'domain_name': domain_name
        });
    }
    
    // Check that domain name is valid and can be issued by registrar
    let domain_name_ascii = validateDomain(domain_name);
    if (domain_name_ascii == null) {
        return res.status(401).json({
            'success': false,
            'status_text': 'DOMAIN_NAME_INVALID',
            'status_code': 401,
            'try_again': false,
            'domain_name': domain_name
        });
    }
    let tld = domain_name_ascii.includes('.') ? domain_name_ascii.substring(domain_name_ascii.indexOf('.') + 1) : '.';
    if (!checkRegistrarDomainAuthorityForRegistration(registrar_id, domain_name_ascii)) {
        return res.status(403).json({
            'success': false,
            'status_text': 'REGISTRY_LACKS_DOMAIN_REGISTRATION_AUTHORITY',
            'status_code': 403,
            'try_again': false,
            'domain_name': domain_name
        });
    }
    // Check that domain name is not already registered
    let qres0 = await client.query('SELECT domain_name FROM public.domains WHERE domain_name = $1', [domain_name_ascii]);
    if (qres0.rowCount !== 0) {
        return res.status(409).json({
            'success': false,
            'status_text': 'DOMAIN_NAME_EXISTED',
            'status_code': 409,
            'try_again': false,
            'domain_name': domain_name
        });
    }
    
    critical_processes_running += 1;
    // Add domain name to the database
    let qres1 = await client.query(
        'INSERT INTO public.domains(domain_name, domain_name_original, tld, registrar_id) VALUES($1, $2, $3, $4)',
        [
            domain_name_ascii,
            domain_name,
            tld,
            registrar_id
        ]
    );
    
    // Assume CoreDNS for now
    let dns_ct = fs.readFileSync(maindir + '/dns/dns_ct').toString().split(' '); // date, then daily count
    
    let cdate = `${setNumStrLen(date.getUTCFullYear(),4)}${setNumStrLen(date.getUTCMonth())}${setNumStrLen(date.getUTCDate())}`;
    
    if (parseInt(dns_ct[0]) < parseInt(cdate)) {
        dns_ct[0] = cdate;
        dns_ct[1] = '0';
    }
    
    dns_ct[1] = (parseInt(dns_ct[1]) + 1).toString();
    
    fs.writeFileSync(dns_cfg['zones-dir'] + '/db.' + domain_name_ascii,
        `$ORIGIN ${domain_name_ascii}.\n$TTL 3600\n\n` + 
        `@ IN SOA ns1.${domain_name_ascii}. hostmaster.${domain_name_ascii}. ( ; SEPARATE HERE\n` +
        `\t${dns_ct[0] + dns_ct[1]} ; SEPARATE HERE\n\t3600\n\t600\n\t1209600\n\t300\n)\n ; SEPARATE HERE\n`
    );
    
    fs.chownSync(
        dns_cfg['zones-dir'] + '/db.' + domain_name_ascii,
        parseInt(process.env.COREDNS_USER),
        parseInt(process.env.COREDNS_GROUP)
    );
    fs.chmodSync(dns_cfg['zones-dir'] + '/db.' + domain_name_ascii, 0o640);
    
    fs.writeFileSync(maindir + '/dns/dns_ct', dns_ct[0] + ' ' + dns_ct[1]);
    
    const originalStat = fs.statSync(dns_cfg['zones-dir']);
    let conf_new_entry = `file ${dns_cfg['zones-dir']}/db.${domain_name_ascii} ${domain_name_ascii} {\n    reload 30s\n    fallthrough\n}`;
    fs.writeFileSync(dns_cfg['zones-conf'] + '.tmp', fs.readFileSync(dns_cfg['zones-conf']).toString() + '\n\n' + conf_new_entry);
    
    fs.chmodSync(dns_cfg['zones-conf'] + '.tmp', originalStat.mode & 0o7777);
    fs.chownSync(dns_cfg['zones-conf'] + '.tmp', originalStat.uid, originalStat.gid);
    
    fs.renameSync(dns_cfg['zones-conf'] + '.tmp', dns_cfg['zones-conf']);
    
    res.status(201).json({
        'success': true,
        'status_text': 'DOMAIN_SUCCESSFULLY_REGISTERED',
        'status_code': 201,
        'try_again': false,
        'domain_name': domain_name
    });
    
    if (critical_processes_running > 0) critical_processes_running -= 1;
});

app.get('/manage-domain/list-records/:domain', async (req, res) => {
    let date = new Date();
    let timenow = date.getTime();
    let authtokenjson = JSON.parse(req.header('Authorization'));
    let authtoken = authtokenjson['authtoken'];
    let timeauth = authtokenjson['timeauth'];
    let registrar_id = authtokenjson['registrar_id'];
    
    if (timeauth + timegrace < timenow || timeauth > timenow + timegrace) {
        return res.status(401).json({
            'success': false,
            'status_text': 'AUTHENTICATION_TOKEN_TOO_OLD',
            'status_code': 401,
            'records': []
        });
    }
    
    let domain_name_original = req.params.domain;
    let domain_name = validateDomain(domain_name_original);
    
    if (domain_name == null) {
        return res.status(422).json({
            'success': false,
            'status_text': 'DOMAIN_NAME_INVALID',
            'status_code': 422,
            'records': []
        });
    }
    
    // Ascertain request origin
    let authtokendata = {
        timeauth,
        registrar_id,
        'domain_name': domain_name,
        'intent': 'list_records'
    }
    
    
    let public_key_location = registrar_cfgs[registrar_id]['public-key']['filename'];
    public_key_location = public_key_location.startsWith('/') ? public_key_location : maindir + '/' + public_key_location;
    if (!fs.existsSync(public_key_location)) {
        res.status(401).json({
            'success': false,
            'status_text': 'REGISTRAR_AUTHENTICATION_PUBLIC_KEY_NOT_FOUND',
            'status_code': 401,
            'records': []
        });
        console.error(`[ERROR @ ${getTimestamp()}] Failed to find public key for registrar ${registrar_id}.`);
        return;
    }
    let registrar_public_key = fs.readFileSync(public_key_location).toString();
    let authsuccess = await check_ml_dsa_87_signature(authtoken, JSON.stringify(authtokendata), registrar_public_key);
    
    if (!authsuccess) {
        return res.status(401).json({
            'success': false,
            'status_text': 'INVALID_CREDENTIALS',
            'status_code': 401,
            'records': []
        });
    }
    
    // Check the registrar of the domain
    let qres = await client.query(
        'SELECT 1 FROM public.domains WHERE domain_name = $1 AND registrar_id = $2',
        [domain_name, registrar_id]
    );
    
    if (qres.rowCount === 0) {
        return res.status(404).json({
            'success': false,
            'status_text': 'DOMAIN_NOT_REGISTERED_UNDER_REGISTRAR',
            'status_code': 404,
            'records': []
        });
    }
    
    // Find the file with the domain records and extract DNS records and default TTL
    let domain_records_file_text = fs.readFileSync(dns_cfg['zones-dir'] + '/db.' + domain_name).toString();
    let domain_records_full = await dnszone.bind.parseZoneFile(domain_records_file_text);
    
    let ttl_default = undefined;
    let records = [];
    let origin = domain_name + '.';
    
    for (let record of domain_records_full) {
        if ('$TTL' in record) {
            ttl_default = record['$TTL'];
            continue;
        }
        
        if ('$ORIGIN' in record) {
            origin = record['$ORIGIN'];
            continue;
        }
        
        if (record['type'] === undefined || record['type'] === 'SOA') continue;
        
        if (record['owner'] === undefined || record['class'] === undefined) continue;
        
        let data = undefined;
        switch (record['type']) {
            case 'A':
                data = record['address'];
                break;
            case 'TXT':
                data = record['data'];
                break;
            default:
                break;
        }
        
        if (data === undefined) continue;
        
        let name = record['owner'].slice(0, -origin.length);
        if (name === '') name = '@';
        
        records.push({
            'type': record['type'],
            'name': name,
            'ttl': record['ttl'],
            'data': data
        });
    }
    
    // Return the final records
    res.status(200).json({
        'success': true,
        'status_text': 'ALL_APPLICABLE_RECORDS_FOUND',
        'status_code': 200,
        'records': records,
        'ttl_default': ttl_default
    });
});

https.createServer(options, app).listen(port, () => {
    console.log(`[INFO @ ${getTimestamp()}] Server listening on port ${port}.`);
});