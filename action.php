<?php

use dokuwiki\plugin\oauth\Adapter;
use dokuwiki\plugin\oauthazure\Azure;

/**
 * Service Implementation for Azure authentication
 */
class action_plugin_oauthazure extends Adapter
{
    /** @inheritdoc */
    public function registerServiceClass()
    {
        return Azure::class;
    }

    /**
     * @inheritdoc
     * @throws \OAuth\Common\Exception\Exception
     */
    public function logout()
    {
        /** @var Azure */
        $oauth = $this->getOAuthService();
        $oauth->logout();
    }

    /** * @inheritDoc */
    public function getUser()
    {
        /** @var Azure */
        $oauth = $this->getOAuthService();
        $data = array();
        $grouplinks = $this->getConf('grouplinks');

        $url = $oauth->getEndpoint(Azure::ENDPOINT_USERINFO);
        $raw = $oauth->request($url);

        $group_raw = $oauth->request("https://graph.microsoft.com/v1.0/me/memberof");
        if (!$group_raw) throw new OAuthException('Failed to fetch data from memberof endpoint');
	$group_result = json_decode($group_raw, true);
        if (!$group_result) throw new OAuthException('Failed to parse data from memberof endpoint');

        if (!$raw) throw new OAuthException('Failed to fetch data from userinfo endpoint');
        $result = json_decode($raw, true);
        if (!$result) throw new OAuthException('Failed to parse data from userinfo endpoint');

	$group_list = [];
	foreach($group_result["value"] as $group){
	    if(in_array($group["id"],$grouplinks)){
		if(strpos($group["displayName"], "-") !== false){
		    $final = explode("-",$group["displayName"])[1];
		    array_push($group_list, $final);
		}else{
		    array_push($group_list, $group["displayName"]);
		}
	    }
        }

	$result['groups'] = array_merge((array)$result['groups'], $group_list);

        $data = array();
        $data['user'] = $result['name'];
        $data['name'] = $result['name'];
        $data['mail'] = $result['email'];
        $data['grps'] = $result['groups'];

        return $data;
    }

    /** @inheritdoc */
    public function getScopes()
    {
        return array(Azure::SCOPE_OPENID);
    }

    /** @inheritDoc */
    public function getLabel()
    {
        return $this->getConf('label');
    }

    /** @inheritDoc */
    public function getColor()
    {
        return $this->getConf('color');
    }
}
