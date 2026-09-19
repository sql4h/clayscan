import securityHeaders from './securityHeaders.js';
import cookies from './cookies.js';
import clickjacking from './clickjacking.js';
import cors from './cors.js';
import infoDisclosure from './infoDisclosure.js';
import credentials from './credentials.js';
import discoveredEndpoints from './discoveredEndpoints.js';
import sensitiveFiles from './sensitiveFiles.js';
import outdatedLibraries from './outdatedLibraries.js';
import reflectedXss from './reflectedXss.js';
import sqli from './sqli.js';
import openRedirect from './openRedirect.js';
import csrf from './csrf.js';
import mixedContent from './mixedContent.js';
import commandInjection from './commandInjection.js';
import pathTraversal from './pathTraversal.js';
import ssti from './ssti.js';
import nosqlInjection from './nosqlInjection.js';
import sensitiveDataApi from './sensitiveDataApi.js';
import jwt from './jwt.js';
import graphql from './graphql.js';
import httpMethods from './httpMethods.js';
import hostHeaderInjection from './hostHeaderInjection.js';
import blindInjection from './blindInjection.js';
import storedXss from './storedXss.js';
import idor from './idor.js';
import ssrf from './ssrf.js';
import xxe from './xxe.js';
import requestSmuggling from './requestSmuggling.js';

export const allChecks = [
  securityHeaders,
  cookies,
  clickjacking,
  csrf,
  mixedContent,
  infoDisclosure,
  credentials,
  discoveredEndpoints,
  outdatedLibraries,
  sensitiveDataApi,
  jwt,

  cors,
  sensitiveFiles,
  openRedirect,
  reflectedXss,
  sqli,
  commandInjection,
  pathTraversal,
  ssti,
  nosqlInjection,
  graphql,
  httpMethods,
  hostHeaderInjection,
  blindInjection,
  storedXss,
  idor,
  ssrf,
  xxe,
  requestSmuggling,
];

export const passiveChecks = allChecks.filter((c) => c.phase === 'passive');
export const activeChecks = allChecks.filter((c) => c.phase === 'active');
