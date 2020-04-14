/**
 * Any intiialisation processes that are required, but which should not
 * run during the test processes
 */

// process any patches to the base configurations
validConfigIds().forEach((id) => {
    processConfigPatches(id);
});
