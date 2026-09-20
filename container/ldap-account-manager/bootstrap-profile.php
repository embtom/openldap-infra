#!/usr/bin/php
<?php

require_once '/usr/share/ldap-account-manager/lib/config.inc';

$profileName = getenv('LAM_PROFILE_NAME');
$serverUrl = getenv('LAM_SERVER_URL');
$baseDn = getenv('LAM_BASE_DN');
$logDestination = getenv('LAM_LOG_DESTINATION');

if ($profileName === false || $serverUrl === false || $baseDn === false || $logDestination === false) {
    fwrite(STDERR, "LAM profile settings are required.\n");
    exit(1);
}

$profileManager = new ServerProfilePersistenceManager();
$profile = $profileManager->loadProfile($profileName);
$profile->set_ServerURL($serverUrl);
$profile->setUseTLS('no');
$profile->set_Suffix('user', 'ou=People,' . $baseDn);
$profile->set_Suffix('group', 'ou=Groups,' . $baseDn);
$profile->set_Adminstring('cn=admin,' . $baseDn);
$profile->setServerDisplayName('OpenLDAP');

$typeSettings = $profile->get_typeSettings();
$typeSettings['modules_user'] = 'inetOrgPerson,posixAccount,shadowAccount,sambaSamAccount';
$typeSettings['modules_group'] = 'posixGroup,sambaGroupMapping,groupOfNames';
$profile->set_typeSettings($typeSettings);

$moduleSettings = $profile->get_moduleSettings();
foreach ([
    'sambaSamAccount_lmHash',
    'sambaSamAccount_hideHomeDrive',
    'sambaSamAccount_hideHomePath',
    'sambaSamAccount_hideProfilePath',
    'sambaSamAccount_hideLogonScript',
    'sambaSamAccount_hideSambaPwdLastSet',
    'sambaSamAccount_hideWorkstations',
    'sambaSamAccount_hideLogonHours',
    'sambaSamAccount_hideTerminalServer',
] as $setting) {
    $moduleSettings[$setting] = ['false'];
}
$moduleSettings['sambaSamAccount_lmHash'] = ['yes'];
$moduleSettings['posixAccount_user_minUID'] = ['10000'];
$moduleSettings['posixAccount_user_maxUID'] = ['60000'];
$moduleSettings['posixGroup_group_minGID'] = ['10000'];
$moduleSettings['posixGroup_group_maxGID'] = ['60000'];
$profile->set_moduleSettings($moduleSettings);

$profileManager->saveProfile($profile, $profileName);

$mainConfig = new LAMCfgMain();
$mainConfig->default = $profileName;
$mainConfig->logDestination = $logDestination;
$mainConfig->save();
