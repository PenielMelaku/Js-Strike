/**
 * utils.js — Planted prototype pollution vulnerabilities.
 */

// ============================================================
// Prototype pollution via recursive merge (no __proto__ filtering)
// ============================================================

function deepMerge(target, source) {
    for (var key in source) {
        if (typeof source[key] === "object" && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

function deepClone(obj) {
    var clone = {};
    for (var key in obj) {
        if (typeof obj[key] === "object" && obj[key] !== null) {
            clone[key] = deepClone(obj[key]);
        } else {
            clone[key] = obj[key];
        }
    }
    return clone;
}

function extend(target, source) {
    Object.keys(source).forEach(function(key) {
        target[key] = source[key];
    });
    return target;
}

// Direct __proto__ access patterns
function setNestedValue(obj, path, value) {
    var keys = path.split(".");
    var current = obj;
    for (var i = 0; i < keys.length - 1; i++) {
        if (!current[keys[i]]) current[keys[i]] = {};
        current = current[keys[i]];
    }
    // If path is __proto__.polluted, this is a vulnerability
    current[keys[keys.length - 1]] = value;
}

// Bracket access to __proto__
function unsafeSet(obj, key, value) {
    obj["__proto__"][key] = value;  // direct prototype pollution
}

// Object.assign usage
function mergeDefaults(config) {
    return Object.assign({}, defaults, config);
}
