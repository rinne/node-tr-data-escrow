declare module 'optist' {
  /** One option definition for {@link Optist.opts}. */
  interface OptDef {
    shortName?: string | string[];
    longName?: string | string[];
    hasArg?: boolean;
    required?: boolean;
    defaultValue?: string;
    multi?: boolean;
    optArgCb?: (arg: string) => unknown;
    requiresAlso?: string | string[];
    conflictsWith?: string | string[];
    /** Env var name used as the value when the option is not on the command line. */
    environment?: string;
    description?: string;
  }

  class Optist {
    o(
      shortName?: string | string[],
      longName?: string | string[],
      hasArg?: boolean,
      required?: boolean,
      defaultValue?: string,
      multi?: boolean,
      optArgCb?: (arg: string) => unknown,
      requiresAlso?: string | string[],
      conflictsWith?: string | string[],
      environment?: string,
    ): this;
    opts(defs: OptDef[]): this;
    describeOpt(name: string, description: string): this;
    additional(restRequireMin?: number, restRequireMax?: number): this;
    help(command?: string): this;
    parse(av?: string[], restRequireMin?: number, restRequireMax?: number): this;
    value(name: string): any;
    values(): Record<string, unknown>;
    rest(): string[];
  }

  export = Optist;
}
