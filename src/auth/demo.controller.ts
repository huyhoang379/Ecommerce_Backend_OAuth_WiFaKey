import { Body, Controller, Post, BadRequestException } from '@nestjs/common';

@Controller('demo')
export class DemoController {
  @Post('exchange-token')
  async exchangeToken(@Body('code') code: string) {
    console.log('Received Code from Frontend:', code);

    if (!code) {
      throw new BadRequestException('Code is missing');
    }

    // 1. Cấu hình thông tin IdP
    const tokenEndpoint = 'http://localhost:8080/oauth2/token'; // Thay bằng URL thật
    const clientId = '63d7d535-2d4f-444d-8139-de9318bd5bd8'; // Thay bằng Client ID thật
    const clientSecret = 'c3379466-7492-4415-80c8-86c86647203b'; // Thay bằng Secret thật
    // Redirect URI này PHẢI TRÙNG KHỚP 100% với cái mà Frontend dùng để lấy code
    // const redirectUri = 'http://localhost:3000/client-auth-demo/get-code';

    // 2. Chuẩn bị dữ liệu gửi sang IdP (x-www-form-urlencoded)
    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('client_id', clientId);
    params.append('client_secret', clientSecret);
    params.append('code', code);
    // params.append('redirect_uri', redirectUri);

    try {
      // 3. Gọi IdP để đổi code lấy token
      const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params,
      });

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const data = await response.json();

      if (!response.ok) {
        console.error('IdP Error:', data);
        throw new BadRequestException(data);
      }

      // 4. Trả kết quả (Access Token) về cho Frontend
      return {
        message: 'Exchange successful',
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        idp_response: data, // Frontend sẽ nhận được access_token, refresh_token ở đây
      };
    } catch (error) {
      console.error('Exchange Failed:', error);
      throw new BadRequestException('Failed to exchange token with IdP');
    }
  }
}
