# Generated by Django 4.0.1 on 2022-02-07 16:46

from django.db import migrations, models
import utils.rename


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_active', models.BooleanField(default=True, verbose_name='Активный?')),
                ('is_staff', models.BooleanField(default=False, verbose_name='Админ?')),
                ('is_superuser', models.BooleanField(default=False, verbose_name='СуперАдмин?')),
                ('password', models.CharField(default='pbkdf2_sha256$320000$7F9EJpVAnq0bUJJeQPNX1Q$7MI1tDK3Vxeh2q/mNBLT8pF4ZqIaloIDNCwJbZbhXD0=', max_length=128, verbose_name='Пароль')),
                ('fullname', models.CharField(blank=True, max_length=300, null=True, verbose_name='Полное имя')),
                ('position', models.CharField(blank=True, max_length=300, null=True, verbose_name='Позиция')),
                ('workPhone', models.CharField(blank=True, max_length=300, null=True, verbose_name='Рабочий телефон')),
                ('personalPhone', models.CharField(blank=True, max_length=300, null=True, verbose_name='Личный телефон')),
                ('workEmail', models.EmailField(blank=True, max_length=254, null=True, verbose_name='Рабочий email')),
                ('email', models.EmailField(blank=True, default=None, max_length=254, null=True, unique=True, verbose_name='Личный email')),
                ('workWebsite', models.URLField(blank=True, null=True, verbose_name='Рабочий сайт')),
                ('otherWebsite', models.URLField(blank=True, null=True, verbose_name='Другой любой сайт')),
                ('fontFamily', models.CharField(blank=True, choices=[['ABHAYA_LIBRE', 'ABHAYA_LIBRE'], ['ALLERTA_STENCIL', 'ALLERTA_STENCIL'], ['ANTON', 'ANTON'], ['BELLOTA_TEXT', 'BELLOTA_TEXT'], ['BLACK_OPS_ONE', 'BLACK_OPS_ONE'], ['CALLIGRAFFITTI', 'CALLIGRAFFITTI'], ['CHATHURA', 'CHATHURA'], ['CINZEL_DECORATIVE', 'CINZEL_DECORATIVE'], ['CODYSTAR', 'CODYSTAR'], ['FASTER_ONE', 'FASTER_ONE'], ['ICELAND', 'ICELAND'], ['KANIT', 'KANIT'], ['MODAK', 'MODAK'], ['MONOFETT', 'MONOFETT'], ['MONOTON', 'MONOTON'], ['NIXIE_ONE', 'NIXIE_ONE'], ['PINYON_SCRIPT', 'PINYON_SCRIPT'], ['PLASTER', 'PLASTER'], ['POIRET_ONE', 'POIRET_ONE'], ['RATIONALE', 'RATIONALE'], ['SAIRA_STENCIL_ONE', 'SAIRA_STENCIL_ONE'], ['STARDOS_STENCIL', 'STARDOS_STENCIL'], ['TEKO', 'TEKO']], default='ABHAYA_LIBRE', max_length=100, null=True, verbose_name='Шрифт')),
                ('avatar', models.ImageField(blank=True, null=True, upload_to=utils.rename.Rename.rename, verbose_name='Аватар')),
                ('bg', models.ImageField(blank=True, null=True, upload_to=utils.rename.Rename.rename, verbose_name='Задний фон')),
                ('uniqueId', models.UUIDField(blank=True, null=True, unique=True, verbose_name='Уникальный id')),
                ('whatsapp', models.URLField(blank=True, null=True, verbose_name='Whatsapp')),
                ('instagram', models.URLField(blank=True, null=True, verbose_name='Instagram')),
                ('facebook', models.URLField(blank=True, null=True, verbose_name='Facebook')),
                ('linkedin', models.URLField(blank=True, null=True, verbose_name='Linkedin')),
                ('telegram', models.URLField(blank=True, null=True, verbose_name='Telegram')),
                ('snapchat', models.URLField(blank=True, null=True, verbose_name='Snapchat')),
                ('tiktok', models.URLField(blank=True, null=True, verbose_name='Tiktok')),
                ('twitter', models.URLField(blank=True, null=True, verbose_name='Twitter')),
                ('youtube', models.URLField(blank=True, null=True, verbose_name='Youtube')),
                ('resetPasswordUUID', models.UUIDField(blank=True, null=True, verbose_name='Ссылка для восстановления пароля')),
                ('resetPasswordDate', models.BigIntegerField(blank=True, null=True, verbose_name='Время восстановления пароля')),
                ('title', models.CharField(blank=True, max_length=200, null=True, verbose_name='Название')),
                ('subtitle', models.CharField(blank=True, max_length=200, null=True, verbose_name='Под заголовок')),
                ('description', models.TextField(blank=True, null=True, verbose_name='Описание')),
                ('address', models.CharField(blank=True, max_length=350, null=True, verbose_name='Адресс')),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.Group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.Permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'Пользователь',
                'verbose_name_plural': 'Пользователи',
            },
        ),
    ]