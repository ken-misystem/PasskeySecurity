<?php
declare(strict_types=1);

namespace Plugin\PasskeySecurity\Controller;

use Eccube\Controller\AbstractController;
use Eccube\Entity\Member;
use Plugin\PasskeySecurity\Resource\Runtime\{Ceremony, ClockEventLog, Policy, PublicPolicy, PublicSettings, Store};
use Symfony\Component\HttpFoundation\{Request, Response};
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

final class SettingsController extends AbstractController
{
    public function __construct(
        private PublicSettings $settings,
        private Store $store,
        private Policy $policy,
        private PublicPolicy $publicPolicy,
        private UserPasswordHasherInterface $hasher,
        private ClockEventLog $clockLog,
    ) {}

    /** @Route("/%eccube_admin_route%/plugin/passkey/config", name="passkey_security_admin_config", methods={"GET","POST"}) */
    public function configure(Request $request): Response
    {
        $user = $this->getUser();
        if (!$user instanceof Member || $user->getWork()?->getId() !== 1 || $user->getAuthority()?->getId() !== 0) {
            throw $this->createAccessDeniedException();
        }
        $ready = $this->settings->ready();
        $shop = $this->settings->migrated();
        $message = '';
        if ($request->isMethod('POST')) {
            try {
                if (!$request->isSecure() || $request->headers->get('Origin') !== $request->getSchemeAndHttpHost()
                    || !$this->isCsrfTokenValid('ps_public_config', $request->request->get('_token'))) {
                    throw new \RuntimeException('config_request');
                }
                if ($this->store->active()) {
                    $this->store->limit('public-config:'.Policy::subject($user), time(), 5);
                }
                if (!$this->hasher->isPasswordValid($user, (string) $request->request->get('password'))) {
                    throw new \RuntimeException('config_password');
                }
                $enrolled = $this->publicPolicy->enrolled($user);
                if ($ready && ($shop || $enrolled)) {
                    $this->policy->staffProof($request->getSession(), $user, time());
                }
                $origin = (string) $request->request->get('origin');
                if ($origin !== $request->getSchemeAndHttpHost()) {
                    throw new \RuntimeException('config_origin');
                }
                $required = $shop || $request->request->get('staff_required') === '1';
                if ($required && (!$enrolled || !$this->policy->complete($request->getSession(), $user, time()))) {
                    throw new \RuntimeException('enroll_admin_first');
                }
                $this->settings->save($origin, (string) $request->request->get('name'), $required, $this->store,
                    $request->request->get('staff_session_hours'));
                $this->store->audit(Policy::subject($user), 'public_policy_saved');
                $message = '設定を保存しました。';
            } catch (\Throwable $error) {
                if (Policy::isClockFailure($error)) {
                    $incident = $this->clockLog->rejected($error, 'configure', 'member', $request->getMethod());
                    $url = htmlspecialchars($this->generateUrl('passkey_security_admin_config'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
                    $response = new Response('<!doctype html><html lang="ja"><meta charset="utf-8"><title>認証処理の確認</title>'
                        .'<p>認証処理を完了できませんでした。</p><p>同じ操作を再送せず、2秒以上待って<a href="'.$url
                        .'">画面を開き直し、状態を確認してください</a>。</p>'
                        .($incident === null ? '' : '<p>照会番号：'.$incident.'</p>'), 503, ['Retry-After' => '2']);
                    if ($incident !== null) {
                        $response->headers->set('X-PasskeySecurity-Incident', $incident);
                    }
                    return $this->secureResponse($response);
                }
                if (Store::isTransientDatabaseFailure($error)) {
                    return $this->secureResponse(new Response('認証処理が混み合っています。少し待ってから再度お試しください。',
                        503, ['Retry-After' => '2']));
                }
                $message = match ($error->getMessage()) {
                    'public_staff_session_hours_invalid' => '保持時間は1〜6時間から選択してください。',
                    'security_recent_proof_required' => '設定を保存するには、パスキーまたは認証アプリで再認証してください。',
                    default => '保存できませんでした。店舗URL、現在のパスワード、スタッフの追加認証を確認してください。',
                };
            }
        }

        $nonce = Ceremony::encode(random_bytes(24));
        return $this->secureResponse($this->render('@PasskeySecurity/public_config.twig', [
            'nonce' => $nonce,
            'message' => $message,
            'origin' => $this->settings->get('origin') ?? ($request->isSecure() ? $request->getSchemeAndHttpHost() : ''),
            'name' => $this->settings->get('name') ?? 'アカウント',
            'required' => $this->settings->required(),
            'shop' => $shop,
            'ready' => $this->settings->ready(),
            'staff_session_hours' => $this->settings->staffSessionHours(),
            'staff_session_options' => PublicSettings::STAFF_SESSION_HOURS,
        ]), $nonce);
    }

    private function secureResponse(Response $response, string $nonce = ''): Response
    {
        $response->headers->add([
            'Cache-Control' => 'no-store, private',
            'Referrer-Policy' => 'same-origin',
            'X-Frame-Options' => 'DENY',
            'X-Content-Type-Options' => 'nosniff',
        ]);
        if ($nonce !== '') {
            $response->headers->set('Content-Security-Policy',
                "default-src 'none'; style-src 'nonce-$nonce'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        }
        return $response;
    }
}
