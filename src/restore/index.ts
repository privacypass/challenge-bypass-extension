function handleBackupFileImport(event: Event): void {
    event.stopPropagation();
    event.stopImmediatePropagation();

    const input: HTMLInputElement = <HTMLInputElement>event.target;
    const files: FileList | null  = input.files;
    if (files === null) return;

    let remaining_files = files.length;

    const onFileReadComplete = () => {
        remaining_files--;

        if (remaining_files <= 0) {
            chrome.runtime.sendMessage({ restore: true, tab: { close: true } });
        }
    }

    for (let file_index=0; file_index < files.length; file_index++) {
        const reader = new FileReader();

        reader.onload = function(){
            try {
                if ((typeof reader.result === 'string') && (reader.result.length > 0)) {
                    const backupJSON: string = reader.result;
                    const backup: {[key: string]: string[]} = JSON.parse(backupJSON);

                    chrome.runtime.sendMessage({ restore: true, backup });
                }
            }
            catch(e) {}
            onFileReadComplete();
        };

        reader.onerror = onFileReadComplete;
        reader.onabort = onFileReadComplete;

        reader.readAsText(
            files[file_index]
        );
    }
}


window.addEventListener('DOMContentLoaded', (event) => {
    event.stopPropagation();
    event.stopImmediatePropagation();

    const appName          = chrome.i18n.getMessage('appName');
    const ctaRestorePasses = chrome.i18n.getMessage('ctaRestorePasses');

    window.document.title = appName + ': ' + ctaRestorePasses;

    const input = window.document.createElement('input');
    input.setAttribute('type',       'file');
    input.setAttribute('accept',     'text/plain, application/json, .txt, .json');
    input.setAttribute('multiple',   '');
    input.addEventListener('change', handleBackupFileImport);

    const root = window.document.getElementById('root');
    if (root !== null) {
        const heading = window.document.createElement('h2');
        heading.appendChild(
            window.document.createTextNode(appName)
        );

        const subheading = window.document.createElement('h3');
        subheading.appendChild(
            window.document.createTextNode(ctaRestorePasses)
        );

        root.appendChild(heading);
        root.appendChild(subheading);
        root.appendChild(input);
    }

    input.click();
});
