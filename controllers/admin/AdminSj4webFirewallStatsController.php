<?php

class AdminSj4webFirewallStatsController extends ModuleAdminController
{

    public function __construct()
    {
        $this->bootstrap = true;
        $this->className = 'AdminSj4webFirewallStatsController';
        $this->table = 'sj4web_firewall_stats';
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
    }
}