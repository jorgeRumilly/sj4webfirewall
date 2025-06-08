{block name="content"}
    <div class="card">
        <div class="card-header">
            <p class="h3 card-header-title">
                {l s='Logs for IP:' d='Modules.Sj4webfirewall.Admin'} {$ip}
            </p>
        </div>
        <div class="card-body">
            {if $logs|count > 0}
                <ul class="list-group">
                    {foreach from=$logs item=log}
                        <li class="list-group-item">
                            <strong>{$log.time}</strong> — {$log.reason}
                        </li>
                    {/foreach}
                </ul>
            {else}
                <p>{l s='No logs available for this IP.' d='Modules.Sj4webfirewall.Admin'}</p>
            {/if}
            <br>
            <a href="{$back_link}" class="btn btn-outline-primary">
                {l s='Back to list' d='Modules.Sj4webfirewall.Admin'}
            </a>
        </div>
    </div>
{/block}
