import { createHash } from "node:crypto";
const MAX_CSV_BYTES = 8 * 1024 * 1024;
const MAX_ROWS = 5_000;
const MAX_COLUMNS = 256;
const MAX_FIELD_CHARS = 16_384;
const SAFE_DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
export const REGISTRY_PORTALS = Object.freeze([
    { key: "ca", jurisdiction: "US-CA", name: "California Data Broker Registry", url: "https://cppa.ca.gov/data_broker_registry/", bulk: true, drop: true },
    { key: "vt", jurisdiction: "US-VT", name: "Vermont Data Broker Registry", url: "https://bizfilings.vermont.gov/online/DatabrokerInquire/", bulk: false, drop: false },
    { key: "or", jurisdiction: "US-OR", name: "Oregon Data Broker Registry", url: "https://dfr.oregon.gov/business/licensing/data-broker-registry/Pages/index.aspx", bulk: false, drop: false },
    { key: "tx", jurisdiction: "US-TX", name: "Texas Data Broker Registry", url: "https://texas-sos.appianportalsgov.com/data-broker-registry", bulk: false, drop: false },
]);
function normalize(value) {
    return String(value ?? "").replace(/^\uFEFF/, "").replace(/\u00a0/g, " ").replace(/\s+/g, " ").trim();
}
function parseCsv(text) {
    if (typeof text !== "string" || Buffer.byteLength(text) < 10 || Buffer.byteLength(text) > MAX_CSV_BYTES) {
        throw new Error("rightout_registry_csv_invalid");
    }
    const rows = [];
    let row = [];
    let field = "";
    let quoted = false;
    for (let index = 0; index < text.length; index += 1) {
        const char = text[index];
        if (quoted) {
            if (char === '"' && text[index + 1] === '"') {
                field += '"';
                index += 1;
            }
            else if (char === '"')
                quoted = false;
            else
                field += char;
        }
        else if (char === '"' && field.length === 0)
            quoted = true;
        else if (char === ",") {
            row.push(field);
            field = "";
            if (row.length > MAX_COLUMNS)
                throw new Error("rightout_registry_csv_invalid");
        }
        else if (char === "\n" || char === "\r") {
            if (char === "\r" && text[index + 1] === "\n")
                index += 1;
            row.push(field);
            field = "";
            rows.push(row);
            row = [];
            if (rows.length > MAX_ROWS)
                throw new Error("rightout_registry_csv_invalid");
        }
        else
            field += char;
        if (field.length > MAX_FIELD_CHARS)
            throw new Error("rightout_registry_csv_invalid");
    }
    if (quoted)
        throw new Error("rightout_registry_csv_invalid");
    if (field.length || row.length) {
        row.push(field);
        rows.push(row);
    }
    return rows;
}
function columnMap(rows) {
    const headerIndex = rows.slice(0, 6).findIndex((row) => normalize(row[0]).toLowerCase().startsWith("data broker name:"));
    if (headerIndex < 0)
        throw new Error("rightout_registry_schema_invalid");
    const header = rows[headerIndex].map((value) => normalize(value).toLowerCase());
    const find = (fragments) => header.findIndex((value) => fragments.every((fragment) => value.includes(fragment)));
    const columns = {
        name: find(["data broker", "name:"]),
        website: find(["primary website:"]),
        email: find(["primary contact email"]),
        rightsUrl: find(["exercise their ca consumer privacy act rights"]),
        fcra: find(["regulated by the federal fair credit reporting act"]),
    };
    if (Object.values(columns).some((index) => index < 0))
        throw new Error("rightout_registry_schema_invalid");
    return { headerIndex, columns };
}
function safeHttps(value) {
    const clean = normalize(value);
    if (!clean)
        return null;
    try {
        const url = new URL(clean);
        if (url.protocol !== "https:" || url.username || url.password || !SAFE_DOMAIN.test(url.hostname))
            return null;
        url.hash = "";
        return url.toString();
    }
    catch {
        return null;
    }
}
function safeEmailDomain(value) {
    const clean = normalize(value).toLowerCase();
    const match = clean.match(/^[^@\s]{1,64}@([^@\s]{3,253})$/);
    return match && SAFE_DOMAIN.test(match[1]) ? match[1] : null;
}
export function parseCaliforniaRegistryCsv(text, { sourceUrl = "", retrievedAt = new Date().toISOString() } = {}) {
    if (typeof sourceUrl !== "string" || !/^https:\/\/cppa\.ca\.gov\/data_broker_registry\/registry\d{4}\.csv$/.test(sourceUrl)) {
        throw new Error("rightout_registry_source_invalid");
    }
    const rows = parseCsv(text);
    const { headerIndex, columns } = columnMap(rows);
    const records = [];
    const seen = new Set();
    for (const row of rows.slice(headerIndex + 1)) {
        const name = normalize(row[columns.name]);
        if (!name || name.length > 240)
            continue;
        const website = safeHttps(row[columns.website]);
        const rightsUrl = safeHttps(row[columns.rightsUrl]);
        const emailDomain = safeEmailDomain(row[columns.email]);
        const identity = website ? new URL(website).hostname : `${name.toLowerCase()}|${emailDomain ?? ""}`;
        const brokerRef = `registry_${createHash("sha256").update(identity).digest("hex").slice(0, 24)}`;
        if (seen.has(brokerRef))
            continue;
        seen.add(brokerRef);
        records.push({
            broker_ref: brokerRef,
            name,
            jurisdiction: "US-CA",
            website_domain: website ? new URL(website).hostname : null,
            contact_email_domain: emailDomain,
            rights_domain: rightsUrl ? new URL(rightsUrl).hostname : null,
            fcra_regulated: /^yes\b/i.test(normalize(row[columns.fcra])),
            route: "california_drop_primary_controller_request_fallback",
        });
    }
    if (records.length < 100)
        throw new Error("rightout_registry_record_count_invalid");
    return {
        schema_version: 1,
        jurisdiction: "US-CA",
        source_url: sourceUrl,
        source_sha256: createHash("sha256").update(text).digest("hex"),
        retrieved_at: retrievedAt,
        record_count: records.length,
        fcra_count: records.filter((record) => record.fcra_regulated).length,
        records,
        portals: REGISTRY_PORTALS,
    };
}
export async function readBoundedText(response) {
    const declared = Number(response?.headers?.get?.("content-length") || "0");
    if (!response?.body || declared > MAX_CSV_BYTES)
        throw new Error("rightout_registry_download_invalid");
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done)
                break;
            size += value.byteLength;
            if (size > MAX_CSV_BYTES)
                throw new Error("rightout_registry_download_invalid");
            chunks.push(Buffer.from(value));
        }
    }
    finally {
        reader.releaseLock();
    }
    return Buffer.concat(chunks).toString("utf8");
}
export function registrySummary(snapshot) {
    if (!snapshot || snapshot.schema_version !== 1 || !Array.isArray(snapshot.records))
        throw new Error("rightout_registry_state_invalid");
    return {
        schema_version: 1,
        jurisdiction: snapshot.jurisdiction,
        source_url: snapshot.source_url,
        source_sha256: snapshot.source_sha256,
        retrieved_at: snapshot.retrieved_at,
        record_count: snapshot.record_count,
        fcra_count: snapshot.fcra_count,
        portals: snapshot.portals,
        route: "california_drop_primary_controller_request_fallback",
        raw_contact_addresses_in_report: false,
    };
}
export const __test = { parseCsv, columnMap, safeHttps, safeEmailDomain };
