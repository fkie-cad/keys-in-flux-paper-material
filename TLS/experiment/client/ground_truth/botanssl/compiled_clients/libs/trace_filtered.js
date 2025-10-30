// trace_calls.js
console.log("[INFO] Starting function tracing...");

// Get all loaded modules
var modules = Process.enumerateModules();
console.log("[INFO] Found " + modules.length + " modules");

var totalHooks = 0;

modules.forEach(function(module) {
    // Only process modules containing "botan" in their name
    if (module.name.toLowerCase().indexOf("botan") === -1) {
        return; // Skip this module
    }
    
    console.log("[INFO] Processing module: " + module.name + " @ " + module.base);
    
    try {
        var exports = module.enumerateExports();
        console.log("[INFO] Module " + module.name + " has " + exports.length + " exported functions");
        
        exports.forEach(function(exp) {
            if (exp.type === 'function') {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            console.log("[CALL] " + module.name + "::" + exp.name);
                        }
                    });
                    totalHooks++;
                } catch (e) {
                    console.log("[SKIP] Could not hook " + module.name + "::" + exp.name + " - " + e.message);
                }
            }
        });
    } catch (e) {
        console.log("[ERROR] Could not enumerate exports for " + module.name + " - " + e.message);
    }
});

console.log("[INFO] Tracing setup complete - hooked " + totalHooks + " functions across " + modules.length + " modules");
