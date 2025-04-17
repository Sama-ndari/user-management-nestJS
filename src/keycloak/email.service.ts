// // ```typescript
// import { Injectable, Logger } from '@nestjs/common';
// import * as nodemailer from 'nodemailer';
// import * as handlebars from 'handlebars';
// import * as fs from 'fs';
// import * as path from 'path';

// @Injectable()
// export class EmailService {
//   private transporter: nodemailer.Transporter;
//   private confirmationTemplate: handlebars.TemplateDelegate;

//   constructor() {
//     this.transporter = nodemailer.createTransport(
//       {
//         service: 'gmail',
//         host: 'smtp.gmail.com',
//         port: 465,
//         secure: true,
//         auth: {
//           user: 'sammynegalbert@gmail.com',
//           pass: 'ofvmompziweobxsd',
//         },
//         tls: { rejectUnauthorized: false },
//       },
//       {
//         from: {
//           name: 'Asyst Waangu Marketplace',
//           address: 'no-reply@asystburundi.com',
//         },
//       },
//     );

//     this.confirmationTemplate = this.loadTemplate('template.hbs');
//   }

//   private loadTemplate(templateName: string): handlebars.TemplateDelegate {
//     const templatesFolderPath = path.join('src/resource/template');
//     const templatePath = path.join(templatesFolderPath, templateName);

//     const templateSource = fs.readFileSync(templatePath, 'utf8');
//     return handlebars.compile(templateSource);
//   }

//   async sendVerificationEmail(to: string, link: string): Promise<void> {
//     try {
//       const html = this.confirmationTemplate({
//         message: 'Thank you for signing up with Asyst Waangu Marketplace!',
//         action: 'Please click the button below to verify your email address:',
//         link: link,
//         buttonText: 'Verify Email',
//       });

//       await this.transporter.sendMail({
//         to,
//         subject: 'Verify Your Email - Asyst Waangu Marketplace',
//         html,
//       });
//       console.log(`Verification email sent to ${to}`);
//     } catch (error) {
//       console.error('Error sending verification email:', error);
//       throw new HttpException(`Failed to send verification email: ${error.message}`, HttpStatus.INTERNAL_SERVER_ERROR);
//     }
//   }

//   async sendUserConfirmation(user: string, token: string) {
//     const html = this.confirmationTemplate({
//       message: `Welcome to Asyst Waangu Marketplace! Your temporary password is: ${token}`,
//       action: 'Please log in and change your password.',
//       link: `${process.env.APP_BASE_URL}/login`,
//       buttonText: 'Log In',
//     });

//     await this.transporter.sendMail({
//       to: user,
//       subject: 'Welcome to Asyst Waangu Marketplace',
//       html,
//     });
//   }
// }







// <!DOCTYPE html>
// <html>
// <head>
//   <meta charset="UTF-8">
//   <title>{{subject}}</title>
// </head>
// <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
//   <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
//     <h2 style="color: #007bff;">Asyst Waangu Marketplace</h2>
//     <p>{{message}}</p>
//     <p>{{action}}</p>
//     <a href="{{link}}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 5px;">
//       {{buttonText}}
//     </a>
//     <p>If the button doesn’t work, copy and paste this link into your browser:</p>
//     <p><a href="{{link}}">{{link}}</a></p>
//     <p>Thank you,<br>The Asyst Waangu Marketplace Team</p>
//   </div>
// </body>
// </html>