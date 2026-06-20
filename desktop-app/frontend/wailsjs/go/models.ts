export namespace main {
	
	export class RuleItem {
	    id: string;
	    target: string;
	    action: string;
	
	    static createFrom(source: any = {}) {
	        return new RuleItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.target = source["target"];
	        this.action = source["action"];
	    }
	}
	export class PassSpec {
	    id: string;
	    enabled: boolean;
	    params: Record<string, Array<number>>;
	
	    static createFrom(source: any = {}) {
	        return new PassSpec(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.enabled = source["enabled"];
	        this.params = source["params"];
	    }
	}
	export class ObfuscationRequest {
	    inputJarPath: string;
	    outputJarPath: string;
	    passes: PassSpec[];
	    rules: RuleItem[];
	    allowOptInPasses: boolean;
	    allowRedundantPasses: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ObfuscationRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inputJarPath = source["inputJarPath"];
	        this.outputJarPath = source["outputJarPath"];
	        this.passes = this.convertValues(source["passes"], PassSpec);
	        this.rules = this.convertValues(source["rules"], RuleItem);
	        this.allowOptInPasses = source["allowOptInPasses"];
	        this.allowRedundantPasses = source["allowRedundantPasses"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

