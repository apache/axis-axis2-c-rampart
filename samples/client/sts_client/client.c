#include <trust_sts_client.h>
#include <trust_context.h>
#include <trust_rst.h>
#include <trust_rstr.h>
#include <axutil_env.h>
#include <rampart_constants.h>
#include <neethi_util.h>
#include <neethi_policy.h>

int main(
    int argc, 
    char **argv)
{
    trust_sts_client_t *sts_client = NULL;
    const axutil_env_t *env = NULL;
    const axis2_char_t *address = NULL;
    const axis2_char_t *client_home = NULL;
    
    axis2_char_t *file_name = NULL;
    axis2_char_t *file_name2 = NULL;
    
    axis2_char_t *appliesto = "http://oasis.open.org";
    axis2_char_t *token = "oasis:names:tc:SAML:1.0:assertion";
    axis2_char_t *request_type = "http://schemas.xmlsoap.org/ws/2005/02/RST/Issue";

    trust_context_t *trust_ctx = NULL;
    trust_rst_t *rst = NULL;
	

    /* Set up the environment */
    env = axutil_env_create_all("sts.log", AXIS2_LOG_LEVEL_TRACE);

    /* Set end point reference of echo service */
    address = "http://localhost:9090/axis2/services/saml_sts";
    client_home = "/home/milinda/Projects/axis2c/deploy/client_repo";
    
    file_name = "./client.xml";
    file_name2 = "./service.xml";
    /*http://131.107.72.15/Security_Federation_SecurityTokenService_Indigo/Asymmetric.svc*/
    
    sts_client = trust_sts_client_create(env);
   

    trust_sts_client_set_home_dir(sts_client, env, client_home);
    trust_sts_client_set_issuer_address(sts_client, env, address);
    trust_sts_client_set_issuer_policy_location(sts_client, env, file_name);
    trust_sts_client_set_service_policy_location(sts_client, env, file_name2);
    
    trust_ctx = trust_context_create(env);
    rst = trust_rst_create(env);
    trust_rst_set_wst_ns_uri(rst, env, "http://schemas.xmlsoap.org/ws/2005/02/trust");
    trust_rst_set_token_type(rst, env, token);
    trust_rst_set_appliesto(rst, env, appliesto);
    trust_rst_set_request_type(rst, env, request_type);

    trust_context_set_rst(trust_ctx, env, rst);

    trust_sts_client_request_security_token(sts_client, env, trust_ctx);


	/*Acquire Sec Token*/
	if(trust_context_get_rstr(trust_ctx, env))
	{
		if(trust_rstr_get_requested_security_token(
					trust_context_get_rstr(trust_ctx, env),
					env))
		{
			printf("\n\nReceived Sec Token : %s\n",
					axiom_node_to_string(trust_rstr_get_requested_security_token(
							trust_context_get_rstr(trust_ctx, env),
							env), env)
					);
		}
	}
    
    trust_sts_client_free(sts_client, env);
    
	return 0;
}






















