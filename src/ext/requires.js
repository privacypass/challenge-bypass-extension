/**
 * This file summarizes the external packages required.
 *
 * @author: Alex Davidson
 */

/* exported createShake256 */
/* exported parseKeys */
/* exported assert */
/* exported Buffer */
"use strict";

const createShake256 = require("../src/crypto/keccak/keccak");
const parseKeys = require("parse-asn1");
const assert = require("assert");
const Buffer = require("safe-buffer").Buffer;
