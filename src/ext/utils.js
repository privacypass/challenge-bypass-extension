/* exported patternToRegExp */

"use strict";


/**
 * Convert URL pattern to regex
 * @param {URL} pattern formatted like those passed to listeners
 * @return {Object} Regex object
 */
function patternToRegExp(pattern) {
    if (pattern === LISTENER_URLS) return /^(?:http|https|file|ftp):\/\/.*/;

    let split = /^(\*|http|https|file|ftp):\/\/(.*)$/.exec(pattern);
    if (!split) throw Error("Invalid schema in " + pattern);
    const schema = split[1];
    const fullpath = split[2];
    split = /^([^/]*)\/(.*)$/.exec(fullpath);
    if (!split) throw Error("No path specified in " + pattern);
    const host = split[1];
    const path = split[2];

    // File
    if (schema === "file" && host !== "") {
        throw Error("Non-empty host for file schema in " + pattern);
    }

    if (schema !== "file" && host === "") {
        throw Error("No host specified in " + pattern);
    }

    if (!(/^(\*|\*\.[^*]+|[^*]*)$/.exec(host))) {
        throw Error("Illegal wildcard in host in " + pattern);
    }

    let reString = "^";
    reString += (schema === "*") ? "https*" : schema;
    reString += ":\\/\\/";
    // Not overly concerned with intricacies
    //   of domain name restrictions and IDN
    //   as we're not testing domain validity
    reString += host.replace(/\*\.?/, "[^\\/]*");
    reString += "(:\\d+)?";
    reString += "\\/";
    reString += path.replace("*", ".*");
    reString += "(\\?.*)?";
    reString += "$";

    return RegExp(reString);
}
