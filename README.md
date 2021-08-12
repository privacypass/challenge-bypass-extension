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
          - `tabs.ts`: The listeners which listen on all the tab related events [API](https://developer.chrome.com/docs/extensions/reference/tabs/)
          - `web-requests.ts`: The listeners which listen on all the web request related events [API](https://developer.chrome.com/docs/extensions/reference/webRequest/)
      - `providers`: Contains the provider-specific code of all the Privacy Pass providers in the extension. Currently we have only Cloudflare and hCaptcha
      - `crypto.js`: Legacy crypto code which is still in Vanilla JavaScript
      - `crypto.d.ts`: TypeScript declaration file for the legacy crypto code
      - `global.ts`: Contains all the variables accessible from anywhere
      - `tab.ts`: Tab class to represent a tab and encapsulate everything which is Tab specific
      - `token.ts`: Token class to represent a token and contain all the code related to tokens
  - `popup`: The web app for the popup in the browser toolbar
      - `components`: Contains all the React components
      - `styles`: Contains all the style sheets which are shared among the React components
  - `types.d.ts`: Global Typescript declaration

## Improvements to the previous version

1. The previous build system is only `cat` which concatenates many plain JavaScript files together, we need something more advanced and suitable like webpack. This results to having a single global scope which prevent us from having the same function/variable names in different files.
2. Previously, all the variables can be accessible from anywhere and there are defined independently which are hard to know how they are related.
3. Using vanilla JavaScript without any compiler/transpiler is dangerous. As you can see in the previous build system, you cannot get a compilation error at all because there is no compiler/transpiler. So we decided to use TypeScript for the new version.
4. The popup UI is dynamic, but we use only vanilla JavaScript. It's easier to maintain if we adopt React.
5. Adopt the Object-Oriented Programming paradigm (OOP), so that we know what we are dealing with instead of passing numbers, strings, or plain JavaScript objects which we don't know what they are and what we can do and cannot do with them.
6. More safety using OOP encapsulation. We try to make anything that is unnecessarily accessible unaccessible by making them private properties.
7. Most of the variables should be tab-specific. Not many of them should be global, but in the previous code base, most of them are global. `setConfigId` is a good example. This is why having the Tab class is crucial.
8. The previous code base is time-dependent. As you can see [here](https://github.com/privacypass/challenge-bypass-extension/blob/1ae280/src/ext/background.js#L475), the business logic is completely time-dependent, but Privacy Pass is not related to time at all. This results to many bugs which happen when you do things too fast or too slowly.
9. `config.js` is too huge and used to configure things which shouldn't be configurable. There is a line between what is programmable and what is configurable. If things are so common and so simple, configuration is a good way to define what the program will do. But if they are not so common that it will be reused again, it should be programmable instead of configurable. That's why we need `src/background/providers` for this thing. That directory can be treated as external programmable modules for each Privacy Pass provider.
