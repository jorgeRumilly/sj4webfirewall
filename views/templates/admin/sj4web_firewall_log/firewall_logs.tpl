{block name="content"}
    <div class="card">
        <div class="card-header">
            <p class="h3 card-header-title">
                {l s='Historique des IPs détectées' d='Modules.Sj4webfirewall.Admin'}
            </p>
        </div>
        <div class="card-body">
            {if $firewall_logs|count > 0}
                <table class="table table-striped">
                    <thead>
                    <tr>
                        <th>{l s='Adresse IP' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Score' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Statut' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Visites' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Dernière activité' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Logs' d='Modules.Sj4webfirewall.Admin'}</th>
                        <th>{l s='Actions' d='Modules.Sj4webfirewall.Admin'}</th>
                    </tr>
                    </thead>
                    <tbody>
                    {foreach from=$firewall_logs item=entry}
                        <tr>
                            <td>{$entry.ip}</td>
                            <td>{$entry.score}</td>
                            <td>
                                {if $entry.status == 'blocked'}
                                    <span class="badge badge-danger">{l s='Bloqué' d='Modules.Sj4webfirewall.Admin'}</span>
                                {elseif $entry.status == 'slow'}
                                    <span class="badge badge-warning">{l s='Ralentissement' d='Modules.Sj4webfirewall.Admin'}</span>
                                {else}
                                    <span class="badge badge-success">{l s='Normal' d='Modules.Sj4webfirewall.Admin'}</span>
                                {/if}
                            </td>
                            <td>{$entry.count}</td>
                            <td>{$entry.updated_at}</td>
                            <td>
                                <div class="sjlog_content">
                                    <ul style="margin:0; padding-left:16px;">
                                        {foreach from=$entry.log item=log}
                                            <li><small>{$log.time} - {$log.reason}</small></li>
                                        {/foreach}
                                    </ul>
                                </div>
                            </td>
                            <td>
                                <div class="btn-group">
                                    <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=resetScore&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-sjprimary" title="{l s='Réinitialiser le score' d='Modules.Sj4webfirewall.Admin'}">
                                        <i class="material-icons">restart_alt</i>
                                    </a>
                                    <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=deleteIp&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-sjdanger" title="{l s='Supprimer cette IP' d='Modules.Sj4webfirewall.Admin'}" onclick="return confirm('{l s='Supprimer cette IP ?' d='Modules.Sj4webfirewall.Admin'}');">
                                        <i class="material-icons">delete</i>
                                    </a>
                                    {if $entry.status == 'blocked'}
                                        <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=unblockIp&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-info" title="{l s='Débloquer cette IP' d='Modules.Sj4webfirewall.Admin'}" onclick="return confirm('{l s='Débloquer cette IP sans réinitialiser son score ?' d='Modules.Sj4webfirewall.Admin'}');">
                                            <i class="material-icons">lock_open</i>
                                        </a>
                                    {else}
                                        <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=forceBlock&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-dark" title="{l s='Forcer le blocage immédiat' d='Modules.Sj4webfirewall.Admin'}" onclick="return confirm('{l s='Forcer le blocage immédiat de cette IP ?' d='Modules.Sj4webfirewall.Admin'}');">
                                            <i class="material-icons">gavel</i>
                                        </a>
                                    {/if}
                                    {if $entry.whitelisted}
                                        <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=unwhitelist&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-sjwarning" title="{l s='Retirer de la whitelist' d='Modules.Sj4webfirewall.Admin'}">
                                            <i class="material-icons">block</i>
                                        </a>
                                    {else}
                                        <a href="{$link->getAdminLink('AdminSj4webFirewallLog')|escape:'html'}&action=whitelist&ip={$entry.ip|urlencode}" class="btn btn-sm btn-outline-sjsuccess" title="{l s='Ajouter à la whitelist' d='Modules.Sj4webfirewall.Admin'}">
                                            <i class="material-icons">check_circle</i>
                                        </a>
                                    {/if}
                                </div>
                            </td>
                        </tr>
                    {/foreach}
                    </tbody>
                </table>
            {else}
                <p>{l s='Aucune IP enregistrée pour le moment.' d='Modules.Sj4webfirewall.Admin'}</p>
            {/if}
        </div>
    </div>
{/block}
