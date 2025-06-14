<p>{l s='To enable contact form protection, please follow these steps carefully:' d='Modules.Sj4webfirewall.Admin'}</p>

<ol>
    <li>
        <strong>{l s='Override the contact form controller (if not already done)' d='Modules.Sj4webfirewall.Admin'}</strong>
        <p>{l s='Create or edit the file:' d='Modules.Sj4webfirewall.Admin'} <code>override/modules/contactform/contactform.php</code></p>
        <p>{l s='Make sure it contains the following hook call inside the sendMessage() method:' d='Modules.Sj4webfirewall.Admin'}</p>
        <pre><code>class ContactFormOverride extends Contactform {
    public function sendMessage() {
        Hook::exec('actionContactFormSubmitBefore');
        parent::sendMessage();
    }
}</code></pre>
    </li>

    <li>
        <strong>{l s='Update the contact form template (in your theme)' d='Modules.Sj4webfirewall.Admin'}</strong>
        <p>{l s='Copy the original file from:' d='Modules.Sj4webfirewall.Admin'} <code>modules/contactform/views/templates/widget/contactform.tpl</code></p>
        <p>{l s='To your theme override path:' d='Modules.Sj4webfirewall.Admin'} <code>themes/your_theme/modules/contactform/views/templates/widget/contactform.tpl</code></p>
        <p>{l s='Then, just before the closing </form> tag, add:' d='Modules.Sj4webfirewall.Admin'}</p>
        <pre><code>&lt;input type="hidden" name="sj4web_fw_token" value=""&gt;
&lt;input type="hidden" name="sj4web_fw_ts" id="sj4web_fw_ts" value=""&gt;
&lt;script&gt;
  document.addEventListener('DOMContentLoaded', function () {
    document.getElementById('sj4web_fw_ts').value = Math.floor(Date.now() / 1000);
  });
&lt;/script&gt;</code></pre>
    </li>
</ol>
