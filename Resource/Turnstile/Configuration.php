<?php
declare(strict_types=1);
namespace Plugin\PasskeySecurity\Resource\Turnstile;
final class Configuration
{
    private ?array $loaded=null;
    public function __construct(private string $path) {}
    public function data():array
    {
        if($this->loaded!==null)return $this->loaded;
        if(!file_exists($this->path)){if(getenv('TURNSTILE_REQUIRED')==='1')throw new \RuntimeException('turnstile_config_required');return $this->loaded=['enabled'=>false];}
        if(is_link($this->path)||!is_file($this->path)||realpath($this->path)!==$this->path||(fileperms($this->path)&0077)!==0||filesize($this->path)>8192)throw new \RuntimeException('turnstile_private_config');
        $d=json_decode((string)file_get_contents($this->path),true,8,JSON_THROW_ON_ERROR);
        if(!is_array($d)||!isset($d['enabled'])||!is_bool($d['enabled']))throw new \RuntimeException('turnstile_config');
        if(!$d['enabled']){if(getenv('TURNSTILE_REQUIRED')==='1')throw new \RuntimeException('turnstile_required');return $this->loaded=['enabled'=>false];}
        foreach(['site_key','secret_key','hostname']as$k)if(!isset($d[$k])||!is_string($d[$k])||$d[$k]==='')throw new \RuntimeException('turnstile_config');
        if(!preg_match('/^[a-zA-Z0-9_-]{10,200}$/D',$d['site_key'])||!preg_match('/^[a-zA-Z0-9_-]{10,200}$/D',$d['secret_key'])||!preg_match('/^[a-z0-9.-]+$/D',$d['hostname']))throw new \RuntimeException('turnstile_config');
        // Cloudflare's public testing keys must never be enabled on the real store.
        if(!str_ends_with($d['hostname'],'.test')&&!str_ends_with($d['hostname'],'.invalid')&&(preg_match('/^[123]x0/',$d['site_key'])||preg_match('/^[123]x0/',$d['secret_key'])))throw new \RuntimeException('turnstile_test_key_prohibited');
        return $this->loaded=$d;
    }
}
