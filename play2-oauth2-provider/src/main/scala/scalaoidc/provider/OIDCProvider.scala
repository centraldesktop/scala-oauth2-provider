package scalaoidc.provider

import play.api.mvc._
import scala.language.implicitConversions
import scala.collection.JavaConversions._
import com.nimbusds.openid.connect.sdk.{AuthenticationSuccessResponse, AuthenticationRequest}
import scalaoauth2.provider._

/**
 * Basic Open ID Connect provider trait.
 */
trait OIDCBaseProvider extends OAuth2BaseProvider {

  implicit def play2oidcRequest(request: RequestHeader): AuthenticationRequest = {
    AuthenticationRequest.parse(request.rawQueryString)
  }

  implicit def play2oidcRequest[A](request: Request[A]): AuthenticationRequest = {
    val param: Map[String, Seq[String]] = getParam(request)
    val queryString = param.map { case (k,v) => k -> v.mkString }
    AuthenticationRequest.parse(queryString)
  }
}

/**
 * OIDCProvider supports returning id_token for successful authentication
 *
 * <h3>Create controller for authorization</h3>
 * <code>
 * object OAuth2Controller extends Controller with OIDCProvider {
 *   def idToken = Action { implicit request =>
 *     issueIDToken(new MyDataHandler())
 *   }
 * }
 * </code>
 *
 * <h3>Register routes</h3>
 * <code>
 * GET /oauth2/authorize controllers.OAuth2Controller.idToken
 * </code>
 */
trait OIDCProvider extends OIDCBaseProvider {

  /**
   * Issue access token in DataHandler process and return the response to client.
   *
   * @param dataHandler Implemented DataHander for register access token to your system.
   * @param request Playframework is provided HTTP request interface.
   * @tparam A play.api.mvc.Request has type.
   * @return Request is successful then return JSON to client in OAuth 2.0 format.
   *         Request is failed then return BadRequest or Unauthorized status to client with cause into the JSON.
   */
  def issueIDToken[A, U](dataHandler: DataHandler[U])(implicit request: play.api.mvc.Request[A]): Result = {
    AuthorizationEndpoint.handleRequest(request, dataHandler) match {
      case Left(e) if e.statusCode == 400 => BadRequest(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
      case Left(e) if e.statusCode == 401 => Unauthorized(responseOAuthErrorJson(e)).withHeaders(responseOAuthErrorHeader(e))
      case Right(r: AuthenticationSuccessResponse) => Found(r.getRedirectionURI.toString)
    }
  }
}
