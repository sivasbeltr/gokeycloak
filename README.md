# GoKeycloak Kullanıcı Kimlik Doğrulama ve Yetkilendirme Projesi

Bu proje, Keycloak kimlik doğrulama ve yetkilendirme sistemi ile entegre çalışan bir Go uygulamasıdır. Fiber web çerçevesi kullanılarak geliştirilmiştir ve oturum yönetimi, rol tabanlı erişim kontrolü ve JWT token doğrulama işlevleri sunar.

## Özellikler

- Keycloak ile OAuth2/OpenID Connect entegrasyonu
- Fiber web çerçevesi (v2.52.6) üzerine inşa edilmiş API
- Güvenli oturum yönetimi ve saklama
- Rol tabanlı erişim kontrolü (RBAC) ile özelleştirilebilir yetkilendirme
- JWT token doğrulama ve 검증
- Kullanıcı profil bilgilerine erişim
- Kolay entegre edilebilir API yapısı

## Proje Yapısı

- `main.go` - Ana uygulama girişi ve HTTP sunucusu yapılandırması
- `auth_controller.go` - Kimlik doğrulama işlemleri için kontrolcü
- `middleware.go` - Yetkilendirme middleware'leri (AuthRequired, RolesRequired, JwtRequiredMiddleware)
- `session.go` - Oturum yönetim fonksiyonları

## Kurulum

### Ön Koşullar

- Go 1.19 veya daha yeni sürümü
- Çalışan bir Keycloak sunucusu (v18+ önerilir)
- Keycloak'ta yapılandırılmış realm ve client

### Kurulum Adımları

1. Projeyi klonlayın:
   ```bash
   git clone https://github.com/kullanici/gokeycloak.git
   cd gokeycloak
   ```

2. Bağımlılıkları yükleyin:
   ```bash
   go mod download
   ```

3. `.env` dosyasını oluşturun ve Keycloak yapılandırmanıza göre ayarlayın:
   ```
   # Keycloak Configuration
   KEYCLOAK_URL=https://your-keycloak-server.com
   KEYCLOAK_REALM=your-realm
   KEYCLOAK_CLIENT_ID=your-client-id
   KEYCLOAK_CLIENT_SECRET=your-client-secret
   KEYCLOAK_REDIRECT_URI=http://localhost:3000/callback

   # Application Configuration
   APP_PORT=3000
   SESSION_EXPIRY=86400
   ```

4. Uygulamayı çalıştırın:
   ```bash
   go run .
   ```

## Keycloak Yapılandırması

1. Keycloak admin panelinde bir realm oluşturun
2. Realm içinde bir client oluşturun ve şu ayarları yapın:
   - Client Protocol: `openid-connect`
   - Access Type: `confidential`
   - Valid Redirect URIs: `http://localhost:3000/callback`
   - Web Origins: `http://localhost:3000` veya `*`
3. Client Secret'ı not alın (Credentials sekmesinden)
4. Roller oluşturun ve kullanıcılara atayın (örn. 'admin', 'user')

## API Endpointleri

- `/` - Ana sayfa
- `/login` - Keycloak ile giriş başlatma
- `/callback` - Keycloak'tan geri dönüş işleme
- `/profile` - Kullanıcı profilini görüntüleme (kimlik doğrulama gerektirir)
- `/admin` - Admin rolüne sahip kullanıcılar için özel sayfa
- `/logout` - Oturumu sonlandırma
- `/logout-success` - Başarılı çıkış sayfası
- `/validate-token` - JWT token doğrulama test endpoint'i
- `/access-token` - Aktif kullanıcının erişim token'ını alma

## Güvenlik Notları

- Uygulamanın production ortamında HTTPS ile kullanılması önerilir
- `.env` dosyasını `.gitignore` dosyasına ekleyerek gizli bilgilerin korunduğundan emin olun
- Oturum anahtarlarını düzenli aralıklarla değiştirin
- JWT token'ları güvenli şekilde saklayın ve taşıyın

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Daha fazla bilgi için LICENSE dosyasına bakın.