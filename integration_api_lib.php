<?php
/*  Copyright (C) 2008 Robb Shecter ( greenfabric.com )

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA */

require_once "HTTP/Request2.php";

class BBIntegrationApi {
  public $server_path;
  public $cached_config_info = false;
  public $request;

  public function __construct($url) {
    $this->server_path = $url;
  }

  //------------- Public API ---------------
  public function is_logged_in() {
    return ! ($this->user_info() == NULL);
  }
  
  public function user_info() {
    if ($this->rails_cookie_value() == NULL)
      return NULL;
    $json_data = $this->api_request("user/" . $this->rails_cookie_value());
    return $json_data->{'user'};
  }

  public function login_url() {
    return $this->config_info()->{'login_url'};
  }

  public function logout_url() {
    return $this->config_info()->{'logout_url'};
  }

  //------------- Private methods -------------
  protected function rails_cookie_value() {
    return $_COOKIE[$this->rails_cookie_name()];
  }
  
  protected function rails_cookie_name() {
    return $this->config_info()->{'cookie_name'};
  }

  protected function config_info() {
    if (! $this->cached_config_info) {
      $this->cached_config_info = $this->api_request("config_info");
    }
    return $this->cached_config_info;
  }  

  /**
   * Sends the API request, using HTTP_Request2. In case of an error, we issue a
   * warning, which should be trapped in an error log.
   *
   * @string $query Most likely the endpoint.
   * @return mixed
   */ 
  protected function api_request($query) {
    if (empty($this->server_path)) {
      return;
    }
    
    try {
      if (!($this->request instanceof HTTP_Request2)) {
        $request = new HTTP_Request2($this->server_path . $query);
      } else {
        $request = $this->request;
      }
      $response = $request->send();  
      $body     = json_decode($response->getBody());

      return $body;

    } catch (HTTP_Request2_Exception $e) {
      trigger_error($e->getMessage(), E_USER_WARNING);
    }
  }
}