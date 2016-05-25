<?php

namespace Webmax\Provider;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use League\Fractal\Manager;
use League\Fractal\Serializer\DataArraySerializer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Webmax Provider.
 *
 * @author Frank Bardon Jr. <frankbardon@gmail.com>
 */
class WebmaxServiceProvider implements ServiceProviderInterface
{
    /**
     * {@inheritdoc}
     */
    public function register(Application $app)
    {
        $app['wm.token'] = null;

        $app['fractal'] = $app->share(function() {
            $manager = new Manager();
            $manager->setSerializer(new DataArraySerializer());

            return $manager;
        });

        $app['wm.require_token'] = $app->protect(function(Request $request, Application $application) {
            if (!$request->headers->has('X-Token')) {
                return new Response('No token found', 400);
            }
        });
    }

    /**
     * {@inheritdoc}
     */
    public function boot(Application $app)
    {
        if (!isset($app['wm.secret_callback'])) {
            throw new \RuntimeException('Secret callback "wm.secret_callback" must be defined in the container');
        }

        $this->attachJWTConverter($app);
        $this->attachJsonInterpreter($app);
        $this->attachRootErrorHandler($app);
    }

    /**
     * Attach JSON web token converter
     *
     * @param Application $app
     * @throws RuntimeException When token is invalid
     */
    private function attachJWTConverter(Application $app)
    {
        $app->before(function(Request $request, Application $app) {
            // Fail silently for public requests
            if (!$request->headers->has('X-Token')) {
                return;
            }

            $providedToken = (new Parser())->parse($request->headers->get('X-Token'));
            $secret = $app['wm.secret_callback']($providedToken);

            if (!$providedToken->verify(new Sha256(), $secret)) {
                throw new \RuntimeException('Invalid token signature', 1000);
            }

            $app['wm.token'] = $providedToken;
        }, Application::EARLY_EVENT);
    }

    /**
     * Attach JSON converter
     *
     * Listens to all requests and detects JSON. If found, it will replace the
     * request content with a parsed JSON object.
     *
     * @param Application $app
     */
    private function attachJsonInterpreter(Application $app)
    {
        $app->before(function(Request $request, Application $app) {
            if (0 === strpos($request->headers->get('Content-Type'), 'application/json')) {
                $data = json_decode($request->getContent(), true);
                $request->request->replace(is_array($data) ? $data : array());
            }
        });
    }

    /**
     * Attach common error handling
     *
     * @param Application $app
     */
    private function attachRootErrorHandler(Application $app)
    {
        $app->error(function(\Exception $e, $code) use ($app) {
            return new JsonResponse([
                'code' => $e->getCode(),
                'message' => $e->getMessage(),
            ], 400);
        });
    }
}
