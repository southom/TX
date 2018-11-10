<?php
namespace wayren\helper;

class TX {
    //QQ
    const GET_QQ_AUTH_CODE_URL = "https://graph.qq.com/oauth2.0/authorize";
    const GET_QQ_ACCESS_TOKEN_URL = "https://graph.qq.com/oauth2.0/token";
    const GET_QQ_OPENID_URL = "https://graph.qq.com/oauth2.0/me";
    const GET_QQ_USER_INFO = "https://graph.qq.com/user/get_user_info";
    //wx
    const GET_WX_AUTH_CODE_URL = "https://open.weixin.qq.com/connect/qrconnect";
    const GET_WX_ACCESS_TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
    const GET_WX_OPENID_URL = "https://graph.qq.com/oauth2.0/me";
    const GET_WX_USER_INFO = "https://api.weixin.qq.com/sns/userinfo";

    private static $qqInc=[
            "appid"=>"101520516",
            "appkey"=>"d06078e9d77080e1b2ab904858663ac9",
            "callback"=>"http://home.67it.com/login/qqcallback",
            "scope"=>"get_user_info"];

    private static $wxInc=[
            "appid"=>"wxe654ea903c96d264",
            "secret"=>"e09e80ca4aea950f4a66fbed143ae6c8",
            "callback"=>"http://home.67it.com/login/weixincallback",
            "scope"=>"snsapi_login"];

    /**
     * [qq_login description]
     * @param  [int] $appid    [appid]
     * @param  [string] $callback [回调地址]
     * @param  string $scope    [访问模块]
     * @return [type]           [description]
     */
    public static function qq_login($appid=null,$callback=null){
        //-------生成唯一随机串防CSRF攻击
        $state = md5(uniqid(rand(), TRUE));
        setcookie('state',$state);
        //-------构造请求参数列表
        $keysArr = array(
            "response_type" => "code",
            "client_id" => self::$qqInc['appid'],
            "redirect_uri" => self::$qqInc['callback'],
            "state" => $state,
            "scope" => self::$qqInc['scope']);
        $login_url = self::combineURL(self::GET_QQ_AUTH_CODE_URL, $keysArr);
        header("Location:$login_url");
    }

    public static function qq_token(){
         //--------验证state防止CSRF攻击
        if(!isset($_COOKIE["state"]) || $_GET['state'] != $_COOKIE["state"]){
            self::showError("30001","不好意思，你有问题");
        }
        setcookie("state", "", time()-3600);
        //-------请求参数列表
        $keysArr = array(
            "grant_type" => "authorization_code",
            "client_id" => self::$qqInc['appid'],
            "redirect_uri" => urlencode(self::$qqInc['callback']),
            "client_secret" => self::$qqInc['appkey'],
            "code" => $_GET['code']);
        //------构造请求access_token的url
        $token_url =self::combineURL(self::GET_QQ_ACCESS_TOKEN_URL, $keysArr);
        $response = self::get_contents($token_url);
        if(strpos($response, "callback") !== false){
            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response  = substr($response, $lpos + 1, $rpos - $lpos -1);
            $msg = json_decode($response);
            if(isset($msg->error)){
                self::showError($msg->error, $msg->error_description);
            }
        }
        $params =[];
        parse_str($response, $params);
        return $params["access_token"];
    }

    public static function qq_openid($access_token=''){
        $keysArr = ["access_token" => $access_token];
        $graph_url = self::combineURL(self::GET_QQ_OPENID_URL, $keysArr);
        $response = self::get_contents($graph_url);
        //--------检测错误是否发生
        if(strpos($response, "callback") !== false){
            $lpos = strpos($response, "(");
            $rpos = strrpos($response, ")");
            $response = substr($response, $lpos + 1, $rpos - $lpos -1);
        }
        $user = json_decode($response);
        if(isset($user->error)){
            self::showError($user->error, $user->error_description);
        }
        return $user->openid;
    }

    public static function qq_userinfo($access_token=null,$openid=null)
    {
        $keysArr = array(
            "access_token" => $access_token,
            "oauth_consumer_key" => (int)self::$qqInc["appid"],
            "openid" => $openid);
        $graph_url = self::combineURL(self::GET_QQ_USER_INFO, $keysArr);
        $response = self::get_contents($graph_url);
        return json_decode($response);
    }

    public static function wx_login(){
        //-------生成唯一随机串防CSRF攻击
        $state = md5(uniqid(rand(), TRUE));
        setcookie('state',$state);
        $keysArr = array(
            "appid" => self::$wxInc['appid'],
            "redirect_uri" =>urlencode(self::$wxInc['callback']),
            "response_type" => "code",
            "scope" => self::$wxInc['scope'],
            "state" => $state);
        $login_url = self::combineURL(self::GET_WX_AUTH_CODE_URL, $keysArr);
        header("Location:$login_url");
    }

    public static function wx_baseinfo(){
        if(!isset($_COOKIE["state"]) || $_GET['state'] != $_COOKIE["state"]){
            self::showError("30001","不好意思，你有问题");
        }
        setcookie("state", "", time()-3600);
        $keysArr = array(
            "appid" => self::$wxInc['appid'],
            "secret" => self::$wxInc['secret'],
            "code" => $_GET['code'],
            "grant_type" => "authorization_code");
        $token_url =self::combineURL(self::GET_WX_ACCESS_TOKEN_URL, $keysArr);
        $response = self::get_contents($token_url);
        return json_decode($response);
    }

    public static function wx_userinfo($access_token=null,$openid=null)
    {
        $keysArr = array(
            "access_token" => $access_token,
            "openid" => $openid);
        $graph_url = self::combineURL(self::GET_WX_USER_INFO, $keysArr);
        $response = self::get_contents($graph_url);
        return json_decode($response);
    }

    /**
     * 显示错误信息
     * @param  [type] $code        [description]
     * @param  string $description [description]
     * @return [type]              [description]
     */
    private static function showError($code, $description = '$'){

        echo "<meta charset=\"UTF-8\">";
        if($description == "$"){
            echo "<h3>error:</h3>$code";
            exit(); 
        }else{
            echo "<h3>error:</h3>$code";
            echo "<h3>msg  :</h3>$description";
            exit(); 
        }
    }

    /**
     * combineURL
     * 拼接url
     * @param string $baseURL   基于的url
     * @param array  $keysArr   参数列表数组
     * @return string           返回拼接的url
     */
    public static function combineURL($baseURL,$keysArr){
        $combined = $baseURL."?";
        $valueArr = array();

        foreach($keysArr as $key => $val){
            $valueArr[] = "$key=$val";
        }

        $keyStr = implode("&",$valueArr);
        $combined .= ($keyStr);
        
        return $combined;
    }

    /**
     * get_contents
     * 服务器通过get请求获得内容
     * @param string $url       请求的url,拼接后的
     * @return string           请求返回的内容
     */
    public static function get_contents($url){
        if (ini_get("allow_url_fopen") == "1") {
            $response = file_get_contents($url);
        }else{
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
            curl_setopt($ch, CURLOPT_URL, $url);
            $response =  curl_exec($ch);
            curl_close($ch);
        }

        //-------请求为空
        if(empty($response)){
            self::showError("50001","请求为空");
        }

        return $response;
    }

}
