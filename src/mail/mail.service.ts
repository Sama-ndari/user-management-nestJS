import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;
  private templates: { [key: string]: handlebars.TemplateDelegate } = {};

  constructor() {
    Logger.log('EmailService initialized');
    this.transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE || '',
      host: process.env.SMTP_HOST || '',
      port: process.env.SMTP_PORT || 0,
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER ||'',
        pass: process.env.SMTP_PASS || '',
      },
      tls: { rejectUnauthorized: false },
    }, {
      from: {
        name: process.env.EMAIL_FROM_NAME || '',
        address: process.env.EMAIL_FROM_ADDRESS || '',
      },
    });


    this.loadTemplates();
  }

  private loadTemplates() {
    const templatesFolderPath = path.resolve(__dirname, '..', '..', '..', 'src', 'users', 'mail', 'templates');
    if (!fs.existsSync(templatesFolderPath)) {
      Logger.error(`Templates folder not found at path: ${templatesFolderPath}`);
      return;
    }
    const templateFiles = fs.readdirSync(templatesFolderPath);

    templateFiles.forEach(file => {
      const templateName = path.basename(file, '.hbs');
      const templatePath = path.join(templatesFolderPath, file);
      const templateSource = fs.readFileSync(templatePath, 'utf8');
      this.templates[templateName] = handlebars.compile(templateSource);
    });

    Logger.log('📩 Email templates loaded successfully');
  }

  private async sendEmail(to: string, subject: string, templateName: string, data: any) {
    try {
      if (!this.templates[templateName]) {
        throw new Error(`Template ${templateName} not found`);
      }

      const html = this.templates[templateName](data);
      const mailOptions = { to, subject, html };

      await this.transporter.sendMail(mailOptions);
      Logger.log(`Email sent to ${to}: ${subject}`);
    } catch (error) {
      Logger.error(`Failed to send email to ${to}: ${error.message}`, error.stack);
      throw new Error(`Email sending failed: ${error.message}`);
    }
  }

  async sendLoginCredentials(userEmail: string, username: string, tempPassword: string) {
    await this.sendEmail(userEmail, 'Vos identifiants de connexion', 'account', {
      userEmail,
      tempPassword,
      username,
      loginLink: process.env.LOGIN_URL || '',
      currentYear: new Date().getFullYear(),
    });
  }
  
}