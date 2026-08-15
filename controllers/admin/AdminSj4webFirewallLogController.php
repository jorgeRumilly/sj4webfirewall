<?php

require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStorage.php';

class AdminSj4webFirewallLogController extends ModuleAdminController
{
    protected const LIST_ID = 'firewall_logs';

    public function __construct()
    {
        $this->bootstrap = true;
        $this->className = false;
        $this->table = 'sj4web_firewall_log';
        $this->lang = false;
        $this->explicitSelect = false;
        $this->deleted = false;
        $this->display = 'list';
        $this->module = Module::getInstanceByName('sj4webfirewall');

        parent::__construct();
    }

    public function initContent()
    {
        parent::initContent();

        $this->meta_title = $this->trans('IP Logs - sj4webfirewall', [], 'Modules.Sj4webfirewall.Admin');
        $storage = $this->buildStorage();

        if ((int) Tools::getValue('viewlogs') && Tools::getValue('ip')) {
            $this->renderLogsView($storage, Tools::getValue('ip'));

            return;
        }

        $entries = $storage->getTrackedEntries();
        $entries = $this->markWhitelistedEntries($entries);
        $entries = $this->applyFilters($entries);
        $entries = $this->sortEntries($entries);

        $page = $this->getCurrentPage();
        $limit = $this->getPaginationLimit();
        $offset = ($page - 1) * $limit;

        $total = count($entries);
        $entries = array_slice($entries, $offset, $limit);

        $helper = new HelperList();
        $helper->module = $this->module;
        $helper->shopLinkType = '';
        $helper->simple_header = false;
        $helper->identifier = 'ip';
        $helper->title = $this->trans('Detected IPs History', [], 'Modules.Sj4webfirewall.Admin');
        $helper->table = self::LIST_ID;
        $helper->list_id = self::LIST_ID;
        $helper->token = Tools::getAdminTokenLite('AdminSj4webFirewallLog');
        $helper->currentIndex = $this->context->link->getAdminLink('AdminSj4webFirewallLog', false);
        $helper->show_toolbar = true;
        $helper->listTotal = $total;
        $helper->_default_pagination = 50;
        $helper->_pagination = [20, 50, 100, 300];
        $helper->actions = ['viewlogs', 'resetScore', 'whitelist', 'unwhitelist', 'forceBlock', 'unblockIp', 'deleteIp'];
        $helper->list_skip_actions = $this->buildListSkipActions($entries);
        $helper->tpl_vars['show_toolbar'] = true;
        $helper->tpl_vars['show_pagination'] = true;

        $fieldsList = [
            'ip' => [
                'title' => $this->trans('IP Address', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'filter_key' => 'ip',
            ],
            'country' => [
                'title' => $this->trans('Country', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
                'align' => 'center',
            ],
            'score' => [
                'title' => $this->trans('Score', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
                'search' => false,
            ],
            'status' => [
                'title' => $this->trans('Status', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'select',
                'list' => [
                    'normal' => $this->trans('Normal', [], 'Modules.Sj4webfirewall.Admin'),
                    'slow' => $this->trans('Slow', [], 'Modules.Sj4webfirewall.Admin'),
                    'blocked' => $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin'),
                ],
                'filter_key' => 'status',
                'filter' => true,
                'callback' => 'getStatusLabel',
                'align' => 'center',
            ],
            'count' => [
                'title' => $this->trans('Visits', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'number',
                'align' => 'center',
                'search' => false,
                'filter' => false,
            ],
            'first_seen' => [
                'title' => $this->trans('First Activity', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
            'last_log' => [
                'title' => $this->trans('Last Log', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'text',
            ],
            'updated_at' => [
                'title' => $this->trans('Last Activity', [], 'Modules.Sj4webfirewall.Admin'),
                'type' => 'datetime',
            ],
        ];

        $this->context->smarty->assign('content', $helper->generateList($entries, $fieldsList));
    }

    public function renderList()
    {
        $this->actions = ['resetScore', 'deleteIp', 'whitelist', 'unwhitelist', 'forceBlock', 'unblockIp', 'viewlogs'];

        return parent::renderList();
    }

    public function postProcess()
    {
        parent::postProcess();

        if (Tools::isSubmit('submitResetfirewall_logs')) {
            $_GET = array_filter($_GET, function ($key) {
                return strpos($key, 'firewall_logsFilter_') === false;
            }, ARRAY_FILTER_USE_KEY);
            $_POST = array_filter($_POST, function ($key) {
                return strpos($key, 'firewall_logsFilter_') === false;
            }, ARRAY_FILTER_USE_KEY);
        }

        $action = Tools::getValue('action');
        $ip = Tools::getValue('ip');
        if (!$action || !$ip) {
            return;
        }

        $storage = $this->buildStorage();
        $whitelist = json_decode((string) Configuration::get('SJ4WEB_FW_WHITELIST_IPS'), true) ?: [];

        switch ($action) {
            case 'resetScore':
                $storage->resetIp($ip);
                break;
            case 'deleteIp':
                $storage->deleteIp($ip);
                break;
            case 'whitelist':
                if (!in_array($ip, $whitelist, true)) {
                    $whitelist[] = $ip;
                    Configuration::updateValue('SJ4WEB_FW_WHITELIST_IPS', json_encode(array_values($whitelist)));
                }
                break;
            case 'unwhitelist':
                $whitelist = array_filter($whitelist, function ($item) use ($ip) {
                    return trim((string) $item) !== $ip;
                });
                Configuration::updateValue('SJ4WEB_FW_WHITELIST_IPS', json_encode(array_values($whitelist)));
                break;
            case 'forceBlock':
                $storage->blockIp($ip);
                break;
            case 'unblockIp':
                $storage->unblockIp($ip);
                break;
        }

        Tools::redirectAdmin(self::$currentIndex . '&token=' . Tools::getAdminTokenLite('AdminSj4webFirewallLog'));
    }

    public function getStatusLabel($value, $entry)
    {
        $status = $entry['status'] ?? 'unknown';
        switch ($status) {
            case 'blocked':
                return '<span class="badge badge-danger">' . $this->trans('Blocked', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
            case 'slow':
                return '<span class="badge badge-warning">' . $this->trans('Slow', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
            default:
                return '<span class="badge badge-success">' . $this->trans('Normal', [], 'Modules.Sj4webfirewall.Admin') . '</span>';
        }
    }

    public function displayResetScoreLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=resetScore&ip=' . $ip . '" 
                   title="' . $this->trans('Reset score', [], 'Modules.Sj4webfirewall.Admin') . '"
                   class="btn btn-sm btn-outline-sjprimary"><i class="icon-refresh"></i> ' . $this->trans('Reset', [], 'Admin.Actions') . '</a>';
    }

    public function displayDeleteIpLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=deleteIp&ip=' . $ip . '" 
            title="' . $this->trans('Delete IP', [], 'Modules.Sj4webfirewall.Admin') . '" onclick="return confirm(\'' . $this->trans('Delete this IP?', [], 'Modules.Sj4webfirewall.Admin') . '\');"
            class="btn btn-sm btn-outline-sjdanger"><i class="icon-trash"></i> ' . $this->trans('Delete', [], 'Admin.Actions') . '</a>';
    }

    public function displayWhitelistLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=whitelist&ip=' . $ip . '" 
                title="' . $this->trans('Whitelist this IP', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjsuccess">
        <i class="icon-check"></i> ' . $this->trans('Whitelist', [], 'Modules.Sj4webfirewall.Admin') . '</a>';
    }

    public function displayUnwhitelistLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=unwhitelist&ip=' . $ip . '" 
                title="' . $this->trans('Remove from whitelist', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjwarning">
        <i class="icon-ban"></i> ' . $this->trans('Unwhitelist', [], 'Modules.Sj4webfirewall.Admin') . '</a>';
    }

    public function displayForceBlockLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=forceBlock&ip=' . $ip . '" 
                title="' . $this->trans('Force block', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-dark">
        <i class="icon-lock"></i> ' . $this->trans('Block', [], 'Admin.Actions') . '</a>';
    }

    public function displayUnblockLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&action=unblockIp&ip=' . $ip . '" 
                title="' . $this->trans('Unblock IP', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjsecondary">
        <i class="icon-unlock"></i> ' . $this->trans('Unblock', [], 'Modules.Sj4webfirewall.Admin') . '</a>';
    }

    public function displayViewLogsLink($token, $id, $name = null)
    {
        $ip = urlencode($id);

        return '<a href="' . $this->context->link->getAdminLink('AdminSj4webFirewallLog') . '&viewlogs=1&ip=' . $ip . '" 
                title="' . $this->trans('View logs', [], 'Modules.Sj4webfirewall.Admin') . '"
                class="btn btn-sm btn-outline-sjinfo">
        <i class="icon-search-plus"></i> ' . $this->trans('View', [], 'Admin.Actions') . '</a>';
    }

    protected function renderLogsView(FirewallStorage $storage, $ip)
    {
        $this->meta_title = $this->trans('Logs for IP: %ip%', ['%ip%' => $ip], 'Modules.Sj4webfirewall.Admin');
        $logs = $storage->getLogsForIp($ip);

        $this->context->smarty->assign([
            'ip' => $ip,
            'logs' => $logs,
            'back_link' => $this->context->link->getAdminLink('AdminSj4webFirewallLog'),
        ]);

        $this->setTemplate('logs_view.tpl');
    }

    protected function markWhitelistedEntries(array $entries)
    {
        $whitelist = json_decode((string) Configuration::get('SJ4WEB_FW_WHITELIST_IPS'), true) ?: [];
        foreach ($entries as &$entry) {
            $entry['whitelisted'] = in_array($entry['ip'], $whitelist, true);
        }
        unset($entry);

        return $entries;
    }

    protected function buildStorage()
    {
        return new FirewallStorage(
            (int) Configuration::get('SJ4WEB_FW_SCORE_LIMIT_BLOCK'),
            (int) Configuration::get('SJ4WEB_FW_SCORE_LIMIT_SLOW'),
            (int) Configuration::get('SJ4WEB_FW_BLOCK_DURATION'),
            (int) Configuration::get('SJ4WEB_FW_ALERT_THRESHOLD'),
            '',
            null,
            (bool) Configuration::get('SJ4WEB_FW_ALERT_EMAIL_ENABLED')
        );
    }

    public function applyFilters(array $entries)
    {
        $filterIp = trim((string) $this->getListFilterValue('ip', ''));
        $filterCountry = trim((string) $this->getListFilterValue('country', ''));
        $filterStatus = trim((string) $this->getListFilterValue('status', ''));
        $filterFirstSeen = $this->getListFilterValue('first_seen', []);
        $filterLogs = trim((string) $this->getListFilterValue('last_log', ''));
        $filterUpdatedAtTo = $this->getListFilterValue('updated_at', []);

        if ($filterIp) {
            $entries = array_filter($entries, function ($entry) use ($filterIp) {
                return stripos($entry['ip'], $filterIp) !== false;
            });
        }

        if ($filterCountry) {
            $entries = array_filter($entries, function ($entry) use ($filterCountry) {
                return strtolower((string) $entry['country']) === strtolower($filterCountry);
            });
        }

        if ($filterStatus) {
            $entries = array_filter($entries, function ($entry) use ($filterStatus) {
                return strtolower((string) $entry['status']) === strtolower($filterStatus);
            });
        }

        $filterFirstSeenFrom = '';
        $filterFirstSeenTo = '';
        if (is_array($filterFirstSeen) && count($filterFirstSeen) > 0) {
            $filterFirstSeenFrom = $filterFirstSeen[0];
            $filterFirstSeenTo = $filterFirstSeen[1] ?? '';
        }

        if ($filterFirstSeenFrom || $filterFirstSeenTo) {
            $entries = array_filter($entries, function ($entry) use ($filterFirstSeenFrom, $filterFirstSeenTo) {
                $timestamp = strtotime((string) $entry['first_seen']);
                $firstSeen = strtotime(date('Y-m-d', $timestamp));

                if ($filterFirstSeenFrom && $firstSeen < strtotime($filterFirstSeenFrom)) {
                    return false;
                }
                if ($filterFirstSeenTo && $firstSeen > strtotime($filterFirstSeenTo)) {
                    return false;
                }

                return true;
            });
        }

        if ($filterLogs) {
            $entries = array_filter($entries, function ($entry) use ($filterLogs) {
                return stripos((string) $entry['last_log'], $filterLogs) !== false;
            });
        }

        $filterUpdatedAt = '';
        $filterUpdatedTo = '';
        if (is_array($filterUpdatedAtTo) && count($filterUpdatedAtTo) > 0) {
            $filterUpdatedAt = $filterUpdatedAtTo[0];
            $filterUpdatedTo = $filterUpdatedAtTo[1] ?? '';
        }

        if ($filterUpdatedAt || $filterUpdatedTo) {
            $entries = array_filter($entries, function ($entry) use ($filterUpdatedAt, $filterUpdatedTo) {
                $timestamp = strtotime((string) $entry['updated_at']);
                $updatedAt = strtotime(date('Y-m-d', $timestamp));

                if ($filterUpdatedAt && $updatedAt < strtotime($filterUpdatedAt)) {
                    return false;
                }
                if ($filterUpdatedTo && $updatedAt > strtotime($filterUpdatedTo)) {
                    return false;
                }

                return true;
            });
        }

        return $entries;
    }

    protected function sortEntries(array $entries)
    {
        $orderby = Tools::getValue(self::LIST_ID . 'Orderby');
        $orderway = strtolower((string) Tools::getValue(self::LIST_ID . 'Orderway')) === 'desc' ? SORT_DESC : SORT_ASC;

        if (!$orderby || empty($entries) || !isset($entries[0][$orderby])) {
            return $entries;
        }

        usort($entries, function ($a, $b) use ($orderby, $orderway) {
            $valA = $a[$orderby];
            $valB = $b[$orderby];

            if (
                preg_match('/^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$/', (string) $valA) &&
                preg_match('/^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$/', (string) $valB)
            ) {
                $valA = strtotime((string) $valA);
                $valB = strtotime((string) $valB);
            }

            if (is_numeric($valA) && is_numeric($valB)) {
                $cmp = $valA <=> $valB;
            } else {
                $cmp = strcmp((string) $valA, (string) $valB);
            }

            return $orderway === SORT_DESC ? -$cmp : $cmp;
        });

        return $entries;
    }

    /**
     * Determine les actions a masquer ligne par ligne pour rester lisible.
     *
     * @return array<string, array<int, string>>
     */
    protected function buildListSkipActions(array $entries)
    {
        $skipActions = [
            'whitelist' => [],
            'unwhitelist' => [],
            'forceBlock' => [],
            'unblockIp' => [],
        ];

        foreach ($entries as $entry) {
            $ip = (string) $entry['ip'];

            if (!empty($entry['whitelisted'])) {
                $skipActions['whitelist'][] = $ip;
            } else {
                $skipActions['unwhitelist'][] = $ip;
            }

            if (($entry['status'] ?? 'normal') === 'blocked') {
                $skipActions['forceBlock'][] = $ip;
            } else {
                $skipActions['unblockIp'][] = $ip;
            }
        }

        return $skipActions;
    }

    /**
     * Retourne la valeur d'un filtre genere par HelperList.
     *
     * HelperList prefixe les champs avec le nom du controller sans `Admin`/`Controller`.
     *
     * @param mixed $default
     *
     * @return mixed
     */
    protected function getListFilterValue($key, $default = '')
    {
        $prefixedKey = $this->getListFilterPrefix() . self::LIST_ID . 'Filter_' . $key;
        $legacyKey = self::LIST_ID . 'Filter_' . $key;

        $value = Tools::getValue($prefixedKey, null);
        if ($value === null) {
            $value = Tools::getValue($legacyKey, $default);
        }

        return $value;
    }

    /**
     * Retourne la page courante de la liste HelperList.
     */
    protected function getCurrentPage()
    {
        return max(1, (int) Tools::getValue('submitFilter' . self::LIST_ID, 1));
    }

    /**
     * Retourne la limite de pagination courante.
     */
    protected function getPaginationLimit()
    {
        $limit = (int) Tools::getValue(
            self::LIST_ID . '_pagination',
            isset($this->context->cookie->{self::LIST_ID . '_pagination'})
                ? $this->context->cookie->{self::LIST_ID . '_pagination'}
                : 50
        );

        if (!in_array($limit, [20, 50, 100, 300], true)) {
            $limit = 50;
        }

        return $limit;
    }

    /**
     * Retourne le prefixe interne utilise par HelperList pour ses champs de filtre.
     */
    protected function getListFilterPrefix()
    {
        return Tools::strtolower(str_replace(['admin', 'controller'], '', $this->controller_name));
    }
}
