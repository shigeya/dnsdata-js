// Handler registries: maps from RR type to the factories that build a
// record's ResourceRecordHandler.
//
// The module keeps one default Registry ([default_registry]), which
// register_rr_handler, registerAllHandlers and the registry-less calls
// of ResourceRecord (get_handler(), get_wire_body(builder)) use. Code
// that must not depend on, or change, process-wide state (the
// Verifier) builds its own Registry and passes it explicitly.
//
// Ports dnsdata-go `zone/registry.go`.

import type { ResourceRecord, ResourceRecordHandler, ns_type } from './dns_zone';

// Builds a handler from a record's presentation value.
export type HandlerFactory = (rr: ResourceRecord, value: string) => ResourceRecordHandler;

// Builds a handler straight from RDATA octets, for types whose octets
// do not go through rdata_to_string (SVCB / HTTPS).
export type HandlerRDataFactory = (rr: ResourceRecord, rdata: Uint8Array) => ResourceRecordHandler;

export class Registry {
    private readonly factories = new Map<ns_type, HandlerFactory>();
    private readonly rdata_factories = new Map<ns_type, HandlerRDataFactory>();

    // register installs factory as the handler builder for RRs of type,
    // replacing any earlier one. rdata_factory, when given, decodes a
    // value held in RFC 3597 generic form; without it such a value is
    // decoded through rdata_to_string. A null factory removes the
    // registration.
    register(type: ns_type, factory: HandlerFactory | null, rdata_factory?: HandlerRDataFactory): void {
        if (factory === null) {
            this.factories.delete(type);
            this.rdata_factories.delete(type);
            return;
        }
        this.factories.set(type, factory);
        if (rdata_factory) {
            this.rdata_factories.set(type, rdata_factory);
        } else {
            this.rdata_factories.delete(type);
        }
    }

    // lookup returns the factory registered for type, or undefined.
    lookup(type: ns_type): HandlerFactory | undefined {
        return this.factories.get(type);
    }

    // lookup_rdata returns the RDATA factory registered for type, or
    // undefined.
    lookup_rdata(type: ns_type): HandlerRDataFactory | undefined {
        return this.rdata_factories.get(type);
    }
}

const DEFAULT_REGISTRY = new Registry();

// default_registry returns the module's default Registry, the one
// register_rr_handler and the registry-less ResourceRecord calls use.
export function default_registry(): Registry {
    return DEFAULT_REGISTRY;
}

// register_rr_handler installs factory in the default registry
// (default_registry().register(type, factory, rdata_factory)).
export function register_rr_handler(type: ns_type, factory: HandlerFactory,
                                    rdata_factory?: HandlerRDataFactory): void {
    DEFAULT_REGISTRY.register(type, factory, rdata_factory);
}
