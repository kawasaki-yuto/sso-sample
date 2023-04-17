/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**このコードは、Spring Securityを使用してSAML認証を実装するためのクラスです。具体的には、以下のことを行なっています。
*
* SecurityFilterChainタイプのappビーンを定義し、HttpSecurityを引数に取ります。
* appビーン内で、以下の処理を行います。
* どのリクエストでも認証が必要であることを指定します。
* デフォルトの設定でSAML 2.0認証を有効にします。
* デフォルトの設定でSAML 2.0ログアウトを有効にします。
* 上記の設定情報を元にhttpをビルドし、SecurityFilterChainとして返却します。
* RelyingPartyRegistrationResolver、Saml2AuthenticationTokenConverter、FilterRegistrationBean、RelyingPartyRegistrationRepositoryの4つのビーンを定義しています。
* このクラスは、SAML認証を行うためのいくつかのセキュリティ関連ビーンを提供します。各ビーンの詳細は次のとおりです。
* 
* app: SecurityFilterChainのインスタンスを作成し、SAML認証を構成します。
* relyingPartyRegistrationResolver: RelyingPartyRegistrationRepositoryに登録されたレジストレーション情報を解決して、Saml2AuthenticationTokenConverterに提供します。
* authentication: SAML認証トークンをSpring Securityが処理できる形式に変換し、セキュリティコンテキストに格納します。
* metadata: SAML 2.0メタデータを検索し、レジストレーション情報を抽出します。
* repository: RelyingPartyRegistrationのインスタンスを生成し、リポジトリに登録します。
* このように、Spring Securityを使用してSAML認証を構成する場合、多くの手順が必要であることがわかります。このクラスは、それらすべての手順を包括的に実行するために設計されています。
*/
package example;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.apache.logging.log4j.Logger;
import org.opensaml.saml.saml2.core.Assertion;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class SecurityConfiguration {

	@Autowired
	private UserDetailsService userDetailsService;

	//private final Logger logeer = (Logger) LoggerFactory.getLogger(SecurityConfiguration.class);

    // HttpSecurityを使用して、SecurityFilterChainを作成する。
    @Bean
    SecurityFilterChain app(HttpSecurity http) throws Exception {

		OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(responseToken -> {
            Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                    .createDefaultResponseAuthenticationConverter() 
                    .convert(responseToken);
            Assertion assertion = responseToken.getResponse().getAssertions().get(0);
            String username = assertion.getSubject().getNameID().getValue();
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username); 
			System.out.println("ユーザー名" + username);
            return MySaml2Authentication(userDetails, authentication); 
        });
        // @formatter:off デフォルトのフォーマッターをオフにすることで、可読性を向上させる。
        http
            // 認証されたリクエストのみ許可する。
            .authorizeHttpRequests((authorize) -> authorize
                .anyRequest().authenticated()
            )
            // SAMLログイン構成を追加する（デフォルト設定を使用）。
            .saml2Login(Customizer.withDefaults())
            // SAMLログアウト構成を追加する（デフォルト設定を使用）。
            .saml2Logout(Customizer.withDefaults());
        // @formatter:on デフォルトのフォーマッターをオンにする。

        // SecurityFilterChainを構築して返す。
        return http.build();
    }

    private AbstractAuthenticationToken MySaml2Authentication(UserDetails userDetails,
			Saml2Authentication authentication) {
		return authentication;
	}

	// RelyingPartyRegistrationRepositoryを解決するためのBeanを作成する。
    @Bean
    RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(
            RelyingPartyRegistrationRepository registrations) {
        // registrationIdが"two"のRelyingPartyRegistrationを返すDefaultRelyingPartyRegistrationResolverを返す。
        return new DefaultRelyingPartyRegistrationResolver((id) -> registrations.findByRegistrationId("two"));
    }

    // Saml2AuthenticationTokenConverterを作成するためのBeanを作成する。
    @Bean
    Saml2AuthenticationTokenConverter authentication(RelyingPartyRegistrationResolver registrations) {
        // RelyingPartyRegistrationResolverを使用して、Saml2AuthenticationTokenConverterを構築する。
        return new Saml2AuthenticationTokenConverter(registrations);
    }

    // FilterRegistrationBeanを使用して、Saml2MetadataFilterを追加するBeanを作成する。
    @Bean
    FilterRegistrationBean metadata(RelyingPartyRegistrationResolver registrations) {
        // Saml2MetadataFilterを作成する。
        Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
        // FilterRegistrationBeanでラップし、順序を-101に設定する。
        FilterRegistrationBean filter = new FilterRegistrationBean<>(metadata);
        filter.setOrder(-101);
        return filter;
    }

    // RelyingPartyRegistrationRepositoryを作成するためのBeanを作成する。
    @Bean
    RelyingPartyRegistrationRepository repository(
            @Value("classpath:credentials/rp-private.key") RSAPrivateKey privateKey) {
        // キーのペアを使用して、Saml2X509Credentialを作成する。
        Saml2X509Credential signing = Saml2X509Credential.signing(privateKey, relyingPartyCertificate());
        // RelyingPartyRegistrationsを使用して、RelyingPartyRegistrationを構築する。
        RelyingPartyRegistration two = RelyingPartyRegistrations
                .fromMetadataLocation("https://dev-05937739.okta.com/app/exk4842vmapcMkohr5d7/sso/saml/metadata")
                .registrationId("two").signingX509Credentials((c) -> c.add(signing))
                .singleLogoutServiceLocation("http://localhost:8080/logout/saml2/slo").build();
        // InMemoryRelyingPartyRegistrationRepositoryに登録されたSAML2サービスプロバイダーを返す。
        return new InMemoryRelyingPartyRegistrationRepository(two);
    }

    // Relying Party証明書を取得するためのユーティリティメソッド。
    X509Certificate relyingPartyCertificate() {
        Resource resource = new ClassPathResource("credentials/rp-certificate.crt");
        try (InputStream is = resource.getInputStream()) {
            // rp-certificate.crtファイルから、X.509形式の証明書を読み込んで返す。
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
        catch (Exception ex) {
            throw new UnsupportedOperationException(ex);
        }
    }
}

