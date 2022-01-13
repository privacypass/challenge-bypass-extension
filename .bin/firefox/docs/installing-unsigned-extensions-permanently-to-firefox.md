- - - -

# Add-on signing in Firefox

### What are my options if I want to use an unsigned add-on?

Firefox [Extended Support Release (ESR)](https://www.mozilla.org/firefox/organizations/), Firefox [Developer Edition](https://www.mozilla.org/firefox/developer/) and [Nightly](https://nightly.mozilla.org/) versions of Firefox will allow you to override the setting to enforce the extension signing requirement, by changing the preference `xpinstall.signatures.required` to __false__ in the [Firefox Configuration Editor](https://support.mozilla.org/en-US/kb/about-config-editor-firefox) (`about:config` page). To override the language pack signing requirement, you would set the preference `extensions.langpacks.signatures.required` to __false__. There are also special unbranded versions of Firefox that allow this override. See the MozillaWiki article, [Add-ons/Extension Signing](https://wiki.mozilla.org/Add-ons/Extension_Signing) for more information.

> The source of this post can be found:
> * [here](https://support.mozilla.org/en-US/kb/add-on-signing-in-firefox?#w_what-are-my-options-if-i-want-to-use-an-unsigned-add-on-advanced-users) in HTML format

- - - -

# Installing unsigned extensions permanently to Firefox

<small>2020-11-26</small>

If you have worked with browser extension on Firefox, you likely go to `about:debugging` for installing the extensions temporary, while useful for development, the extension gets removed once Firefox restarts.

Sometimes you may need to test how the extension behaves when Firefox starts, or, just want to leave your extension installed without signing it with the Developer Hub.


## Summary

Gladly, there is a simple solution:
1. Update your extension manifest to include custom `browser_specific_settings`.
2. Disable signature checks while installing extensions.
3. Package your extension as a zip file.
4. Install the extension.
5. Enable signature checks while installing extensions.


### Step 1
Update your `manifest.json` to include a new key, the `id` could be any email:

```json
"browser_specific_settings": {
  "gecko": {
    "id": "test@gmail.com"
  }
}
```

### Step 2
Go to `about:config`, change `xpinstall.signatures.required` to `false`.

### Step 3
Simply run `zip -r -FS ../my-extension.zip * --exclude '*.git*'`.

### Step 4
Go to `about:addons`, and choose the `Install Add-on from file` option, choose the zip file created in the previous step.

### Step 5
Go to `about:config`, change `xpinstall.signatures.required` to `true`.

That's it, you have installed an unsigned extension permanently.

> The source of this post can be found:
> * [here](https://wiringbits.net/browser-extensions/2020/11/27/installing-unsigned-extensions-permanently-to-firefox.html) in HTML format
> * [here](https://github.com/wiringbits/wiringbits.github.io/blob/4f08ae14f53df32809420675d36b21deca081401/_posts/2020-11-26-installing-unsigned-extensions-permanently-to-firefox.md) in Markdown format

- - - -
