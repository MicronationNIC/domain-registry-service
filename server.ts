import 'dotenv/config'
import express from 'express';
const app = express();
import fs from 'fs';
import https from 'https';
import *  as yaml from 'js-yaml';
import { Client } from 'pg';
import { domainToASCII } from 'node:url';
import * as dnszone from '@nictool/dns-zone';
import path from 'node:path';
const maindir = process.env.MAINDIR || '/etc/registryservice';
const port = process.env.PORT || 443;
const timegrace = process.env.TIMEGRACE === undefined ? 5000 : parseInt(process.env.TIMEGRACE); // In milliseconds
const dns_cfg = yaml.load(fs.readFileSync(maindir + '/dns/dns.yaml').toString()) as Record<string, string>;

let critical_processes_running = 0;

var options = {
    key: fs.readFileSync(maindir + 'ssl/privkey.pem', 'utf8'),
    cert: fs.readFileSync(maindir + 'ssl/fullchain.pem', 'utf8')
}

function setNumStrLen(num: number, len?: number | undefined) {
    let numstr: string = num.toString();
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
    return `${now.getUTCFullYear()}-${setNumStrLen(now.getUTCMonth()+1)}-${setNumStrLen(now.getUTCDate())} ${setNumStrLen(now.getUTCHours())}:${setNumStrLen(now.getUTCMinutes())}:${setNumStrLen(now.getUTCSeconds())}.${setNumStrLen(now.getUTCMilliseconds(), 3)} UTC`;
}

/**
 * WARNING: This function does not query postgres to check if the registrar has authority to update an existing domain. This is not for use in amending existing domain name records.
 * @param {string} registrar - The ID of the registrar to check its authority
 * @param {string} domain_name - The full domain name which is intended to be registered
 */
function checkRegistrarDomainAuthorityForRegistration(registrar: string, domain_name: string) {
    if (registrar == undefined) return false;
    if (!(registrar in registrar_cfgs)) return false;
    let cfg = (registrar_cfgs as Record<string, any>)[registrar];
    if (!('tld-authority' in cfg)) return false;
    if (domain_name.endsWith('.')) return false;
    
    let tld = domain_name.includes('.') ? domain_name.substring(domain_name.indexOf('.') + 1) : '.';
    
    for (let authority of cfg['tld-authority']) {
        if (authority['tld'] === tld) {
            if (!authority['exclude'].includes(domain_name)) {
                return true;
            }
        }
    }
    
    return false;
}

const encoder = new TextEncoder();
async function check_ml_dsa_87_signature(signature_b64: string, data: string, key_b64: string) {
    const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js');
    
    try {
        const public_key = Buffer.from(key_b64, 'base64');
        const signature = Buffer.from(signature_b64, 'base64');
        
        if (public_key.length !== 2592 || signature.length !== 4627) {
            return false;
        }
        
        return ml_dsa87.verify(
            signature,
            encoder.encode(data),
            public_key
        );
    } catch {
        return false;
    }
}

function validateDomain(input: any) {
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

async function rfc1035ToJson(filename: string, default_origin?: string) {
    let domain_records_file_text = fs.readFileSync(filename).toString();
    let domain_records_full = await dnszone.bind.parseZoneFile(domain_records_file_text);
    
    let ttl_default = undefined;
    let records = [];
    let origin = default_origin;
    let soa = undefined;
    
    for (let record of domain_records_full) {
        if ('$TTL' in record) {
            if (typeof record['$TTL'] !== 'number') continue;
            ttl_default = record['$TTL'] as number;
            continue;
        }
        
        if ('$ORIGIN' in record) {
            if (typeof record['$ORIGIN'] !== 'string') continue;
            origin = record['$ORIGIN'] as string;
            continue;
        }
        
        if (origin === undefined) {
            console.warn(`[WARN @ ${getTimestamp()}] No origin specified in the record at ${filename}.`)
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
                if (typeof record['address'] === 'string') data = record['address'];
                break;
            case 'AAAA':
                if (typeof record['address'] === 'string') data = record['address'];
                break;
            case 'TXT':
                if (typeof record['data'] === 'string') data = record['data'];
                break;
            default:
                break;
        }
        
        if (data === undefined) continue;
        
        let name = record['owner'].slice(0, -origin.length);
        if (name === '') name = '@';
        if (name.endsWith('.')) name = name.slice(0, -1);
        
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

function updateFileAtomic(filename: string, text: string, returnIfNotExists?: boolean) {
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
    let dns_ct = fs.readFileSync(maindir + '/dns/dns_ct').toString();
    let cdate = `${setNumStrLen(date.getUTCFullYear(),4)}${setNumStrLen(date.getUTCMonth()+1)}${setNumStrLen(date.getUTCDate())}`;
    let serialsplit = dns_ct.split(' ')
    let ctdate = serialsplit[0];
    let ctval = serialsplit[1];
    if (parseInt(cdate) > parseInt(ctdate)) {
        ctdate = cdate;
        ctval = '0';
    } else {
        ctval = (parseInt(ctval) + 1).toString(10);
    }
    fs.writeFileSync(maindir + 'dns/dns_ct', ctdate + ' ' + ctval);
    return cdate + ctval;
}

function prepareTxtRecord(text: string) {
    if (typeof text !== 'string') return '';
    let bytes = encoder.encode(text);
    if (bytes.length === 0) return '""';
    if (bytes.length > 65535) return '""'; // too long
    
    const chunks = [];
    let currentChunk = '';
    let currentByteLen = 0;
    
    for (let byte of bytes) {
        if (currentByteLen === 255) {
            chunks.push(`"${currentChunk}"`);
            currentChunk = '';
            currentByteLen = 0;
        }
        
        switch (byte) {
            case 0x22:
                currentChunk += '\\"';
                break;
            case 0x5c:
                currentChunk += '\\\\';
                break;
            default:
                if (byte < 0x20 || byte > 0x7e) {
                    currentChunk += `\\${byte.toString(10).padStart(3, '0')}`;
                } else {
                    currentChunk += String.fromCharCode(byte);
                }
        }
        
        currentByteLen++;
    }
    
    if (currentByteLen > 0) {
        chunks.push(`"${currentChunk}"`);
    }
    
    return chunks.join(' ');
}

const A_DATA_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])$/;
const AAAA_DATA_REGEX = /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9]))$/;
function updateDomainFile(domain_name: string, json: {
    ttl_default: any;
    records: {
        type: any;
        name: any;
        ttl: any;
        data: any;
    }[];
    origin: string | undefined;
}) {
    let filename = dns_cfg['zones-dir'] + '/db.' + domain_name;
    let text = `$ORIGIN ${json['origin']}\n$TTL ${json['ttl_default']}\n\n`;
    text += `@ IN SOA ns1.${json['origin']} hostmaster.${json['origin']} ${getNewZoneSerial()} 3600 600 1209600 300\n`
    
    for (let record of json['records']) {
        if (!['A', 'AAAA', 'TXT'].includes(record['type'])) continue;
        if (record['name'] !== '@') record['name'] = validateDomain(record['name']);
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
                text += prepareTxtRecord(record['data']);
                break;
        }
    }
    return updateFileAtomic(filename, text, true) ? 'OK' : 'ATOMIC_WRITE_FAIL';
}
// rfc1035ToJson('./cfg/dns/zones/db.pizza.po').then((v) => {console.log(v)});

async function updateRfc1035Record(domain_name: string, idToUpdate: number, newRecord: {
    type: string,
    name: string,
    ttl: number | undefined,
    data: any
}) {
    let filename = dns_cfg['zones-dir'] + '/db.' + domain_name;
    let current = await rfc1035ToJson(filename, domain_name + '.');
    if (idToUpdate > current['records'].length) return 'ID_TOO_BIG';
    current['records'][idToUpdate] = newRecord;
    return updateDomainFile(domain_name, current);
}

function checkForContents(item: {}, contents: Iterable<any>) {
    for (let content of contents) {
        if (!(content in item)) return false;
    }
    return true;
}

if (!checkForContents(process.env, ['COREDNS_USER', 'COREDNS_GROUP'])) {
    console.error(`[FATAL @ ${getTimestamp()}] Some environment variables critical to the functioning of the website are missing.`);
    process.exitCode = 1;
}

async function confirmRegistrarSignature(
    req: express.Request, date: Date, authtokendata: {}
) {
    let authheadertxt = req.header('Authorization');
    if (authheadertxt === undefined) return 'NO_SIGNATURE';
    let authheader = JSON.parse(authheadertxt);
    let timenow = date.getTime();
    let timeauth = authheader['timeauth'];
    let registrar_id = authheader['registrar_id'];
    if (timeauth + timegrace < timenow || timeauth > timenow + timegrace) return 'EXPIRED';
    if (!(registrar_id in registrar_cfgs)) return 'REGISTRAR_INVALID';
    if (!('public-key' in registrar_cfgs[registrar_id]) || !('filename' in registrar_cfgs[registrar_id]['public-key'])) {
        console.error(`[ERROR @ ${getTimestamp()}] No key specified for registrar ${registrar_id}.`);
        return 'NO_PUBLIC_KEY_LISTED';
    }
    let public_key_location = registrar_cfgs[registrar_id]['public-key']['filename'];
    public_key_location = public_key_location.startsWith('/') ? public_key_location : maindir + '/' + public_key_location;
    if (!fs.existsSync(public_key_location)) {
        console.error(`[ERROR @ ${getTimestamp()}] No key exists at the specified location for registrar ${registrar_id}.`);
        return 'NO_KEY';
    }
    let pubkey = fs.readFileSync(public_key_location).toString();
    return await check_ml_dsa_87_signature(authheader['authtoken'], JSON.stringify(authtokendata), pubkey) ? 'OK' : 'SIGNATURE_INCORRECT';
}

// Load postgres
const client = new Client({
    user: process.env.POSTGRES_USER,
    host: process.env.POSTGRES_HOST || 'localhost',
    database: process.env.POSTGRES_DB || 'domain_registry_db',
    password: process.env.POSTGRES_PASSWD,
    port: process.env.POSTGRES_PORT === undefined ? 5432 : parseInt(process.env.POSTGRES_PORT),
});
client.connect();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const registrars = yaml.load(fs.readFileSync(maindir + '/registrars/registrardb.yaml').toString()) as Record<string, string>;
const registrar_cfgs = {} as Record<string, any>
for (let registrar of Object.keys(registrars)) {
    let cfgfile = registrars[registrar].startsWith('/') ? registrars[registrar] : maindir + '/' + registrars[registrar];
    if (!fs.existsSync(cfgfile)) {
        console.error(`[ERROR @ ${getTimestamp()}] Configuration file for ${registrar} does not exist at ${cfgfile}.`);
        registrars
        delete registrars[registrar];
        continue;
    }
    registrar_cfgs[registrar] = yaml.load(fs.readFileSync(cfgfile).toString());
}

app.get('/check-domain-availability', async (req, res) => {
    let registrar_id = req.query.registrar_id?.toString();
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
    if (qres.rowCount !== null && qres.rowCount > 0) {
        return res.status(200).json({
            'success': true,
            'status_text': "DOMAIN_ALREADY_REGISTERED",
            'can_register': false
        });
    }
    
    // See if the domain name is eligible for registration by that registrar
    if (registrar_id === undefined || !checkRegistrarDomainAuthorityForRegistration(registrar_id, domain_name)) {
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
    
    let cdate = `${setNumStrLen(date.getUTCFullYear(),4)}${setNumStrLen(date.getUTCMonth()+1)}${setNumStrLen(date.getUTCDate())}`;
    
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
    
    if (process.env.COREDNS_USER === undefined || process.env.COREDNS_GROUP === undefined) {
        res.status(500).json({
            'success': false,
            'status_text': 'SERVER_MISSING_CRITICAL_CONFIGURATIONS',
            'status_code': 500,
            'try_again': false,
            'domain_name': domain_name
        });
        process.exitCode = 1;
        return;
    }
    
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
    let authheader = req.header('Authorization')
    if (authheader === undefined) {
        return res.status(401).json({
            'success': false,
            'status_text': 'AUTHORIZATION_HEADER_UNDEFINED',
            'status_code': 401,
            'records': []
        });
    }
    
    let authtokenjson = JSON.parse(authheader);
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
    let domain_records_full = await rfc1035ToJson(dns_cfg['zones-dir'] + '/db.' + domain_name, domain_name + '.');
    
    let ttl_default = domain_records_full.ttl_default;
    let records = domain_records_full.records;
    
    // Return the final records
    res.status(200).json({
        'success': true,
        'status_text': 'ALL_APPLICABLE_RECORDS_FOUND',
        'status_code': 200,
        'records': records,
        'ttl_default': ttl_default
    });
});

app.patch('/manage-domain/update-record', async (req, res) => {
    let date = new Date();
    let timeauth = req.body.timeauth;
    let registrar_id = req.body.registrar_id;
    
    let domain_name = validateDomain(req.body.domain_name);
    if (domain_name === null) {
        return res.status(422).json({
            'success': false,
            'status_text': 'INVALID_DOMAIN_NAME',
            'status_code': 422
        });
    }
    
    let type = req.body.type;
    let name = req.body.record_name;
    if (name !== '@') name = validateDomain(name);
    let ttl = req.body.ttl;
    let data = req.body.data;
    let record_id = req.body.record_id;
    
    // Confirm the registrar's signature
    let authtokendata = {
        timeauth,
        registrar_id,
        'intent': 'update-record',
        domain_name,
        type,
        name,
        ttl,
        data,
        record_id
    }
    let sigveri = await confirmRegistrarSignature(req, date, authtokendata);
    if (['NO_PUBLIC_KEY_LISTED', 'NO_KEY'].includes(sigveri)) {
        return res.status(500).json({
            'success': false,
            'status_text': 'SERVER_DOES_NOT_HAVE_REGISTRAR_KEY',
            'status_code': 500
        });
    }
    if (sigveri !== 'OK') {
        return res.status(401).json({
            'success': false,
            'status_text': 'INVALID_REGISTRAR_CREDENTIALS',
            'status_code': 401
        });
    }
    
    // Confirm that the registrar is authorised to make the change
    let qres = await client.query('SELECT registrar_id FROM public.domains WHERE domain_name = $1', [domain_name]);
    if (qres.rowCount === 0) {
        return res.status(404).json({
            'success': false,
            'status_text': 'DOMAIN_DOES_NOT_EXIST_ON_REGISTRY',
            'status_code': 404
        });
    }
    
    if (qres.rows[0]['registrar_id'] !== registrar_id) {
        return res.status(403).json({
            'success': false,
            'status_text': 'DOMAIN_DOES_NOT_BELONG_TO_REGISTRAR',
            'status_code': 403
        });
    }
    
    let record_id_num = parseInt(record_id);
    
    if (Number.isNaN(record_id_num)) {
        return res.status(422).json({
            'success': false,
            'status_text': 'INVALID_RECORD_ID',
            'status_code': 422
        });
    }
    
    let ttl_number = parseInt(ttl);
    
    if (Number.isNaN(ttl_number)) {
        return res.status(422).json({
            'success': false,
            'status_text': 'INVALID_TTL',
            'status_code': 422
        });
    }
    
    // Attempt to make the change
    let update_status = await updateRfc1035Record(domain_name, record_id_num, {
        type,
        name,
        'ttl': ttl_number,
        data
    });
    
    switch (update_status) {
        case 'ID_TOO_BIG':
            return res.status(422).json({
                'success': false,
                'status_text': 'ID_TOO_BIG',
                'status_code': 422
            });
        case 'INVALID_DATA':
            return res.status(422).json({
                'success': false,
                'status_text': 'INVALID_DATA',
                'status_code': 422
            });
        case 'OK':
            return res.status(200).json({
                'success': true,
                'status_text': 'UPDATE_SUCCESSFUL',
                'status_code': 200
            });
        case 'ATOMIC_WRITE_FAIL':
            return res.status(500).json({
                'success': false,
                'status_text': 'ATOMIC_WRITE_FAILED',
                'status_code': 500
            });
    }
    
    console.error(`[ERROR @ ${getTimestamp()}] Poor handling of update_status value ${update_status} in /manage-domains/update-record.`);
    return res.status(500).json({
        'success': update_status === 'OK',
        'status_text': 'POOR_UPDATE_STATUS_HANDLING',
        'status_code': 500
    });
});

app.get('/source-code', (req, res) => {
    if (process.env.SOURCE_CODE) return res.redirect(process.env.SOURCE_CODE);
    return res.status(404).send('Error 404: Not Found');
});

https.createServer(options, app).listen(port, () => {
    console.log(`[INFO @ ${getTimestamp()}] Server listening on port ${port}.`);
});