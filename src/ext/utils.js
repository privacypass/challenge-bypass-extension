/* exported patternToRegExp */

"use strict"


/**
 * Convert URL pattern to regex
 * @param URL pattern, formatted like those pased to listeners
 */
function patternToRegExp(pattern) {
    if (pattern === "<all_urls>") return /^(?:http|https|file|ftp):\/\/.*/;

    let split = /^(\*|http|https|file|ftp):\/\/(.*)$/.exec(pattern);
    if (!split) throw Error("Invalid schema in " + pattern);
    var schema = split[1];
    var fullpath = split[2];
    split = /^([^/]*)\/(.*)$/.exec(fullpath);
    if (!split) throw Error("No path specified in " + pattern);
    var host = split[1];
    var path = split[2];

    // File
    if (schema === "file" && host !== "")
        throw Error("Non-empty host for file schema in " + pattern);

    if (schema !== "file" && host === "")
        throw Error("No host specified in " + pattern);

    if (!(/^(\*|\*\.[^*]+|[^*]*)$/.exec(host)))
        throw Error("Illegal wildcard in host in " + pattern);

    var reString = "^";
    reString += (schema === "*") ? "https*" : schema;
    reString += ":\\/\\/";
    // Not overly concerned with intricacies
    //   of domain name restrictions and IDN
    //   as we're not testing domain validity
    reString += host.replace(/\*\.?/, "[^\\/]*");
    reString += "(:\\d+)?";
    reString += "\\/";
    reString += path.replace("*", ".*");
    reString += "$";

    return RegExp(reString);
}