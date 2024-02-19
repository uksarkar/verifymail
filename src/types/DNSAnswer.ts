import { DNS_RECORD_TYPES } from "../utils/constants";

export default interface DNSAnswer {
    name: string;
    type: keyof typeof DNS_RECORD_TYPES;
    TTL: number | 'auto';
    data?: string | null;
}