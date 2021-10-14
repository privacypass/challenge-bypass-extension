# Privacy Pass Extension

## Build Instruction

```sh
$ npm ci
$ npm run build
```

After that, the `dist` folder will contain all files required by the extension.

## Test Instruction
```sh
$ npm ci
$ npm test
```

## Directory Structure

- `public`: Contains all the assets which are neither the business logic files nor the style sheets
- `src`: Contains all the business logic files and the style sheets
  - `background`: The business logic for the extension background process
      - `listeners`: Contains all the listeners which listen on all the events happened in the browser
          - `tabListener.ts`: The listeners which listen on all the tab related events [API](https://developer.chrome.com/docs/extensions/reference/tabs/)
          - `webRequestListener.ts`: The listeners which listen on all the web request related events [API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
      - `providers`: Contains the provider-specific code of all the Privacy Pass providers in the extension. Currently we have only Cloudflare and hCaptcha
      - `voprf.js`: Legacy crypto code which is still in Vanilla JavaScript
      - `voprf.d.ts`: TypeScript declaration file for the legacy crypto code
      - `tab.ts`: Tab class to represent a tab and encapsulate everything which is Tab specific
      - `token.ts`: Token class to represent a token and contain all the code related to tokens
  - `popup`: The web app for the popup in the browser toolbar
      - `components`: Contains all the React components
      - `styles`: Contains all the style sheets which are shared among the React components
      - `types.d.ts`: Global Typescript declaration
