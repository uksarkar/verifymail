export default interface Options {
    ip: string; // Client IP address
    sender: string; // Email address
    helo: string; // Client EHLO/HELO hostname
    mta: string; // Hostname of the MTA or MX server that processes the message (optional)
    maxResolveCount: number; // Maximum DNS lookups allowed (optional, default: 10)
    maxVoidCount: number; // Maximum empty DNS lookups allowed (optional, default: 2)
    dnsResolverHost: string; // The host URL of the DNS resolver default is `https://dns.google/resolve?name={domain}&type={type}`
}
