# Generated by Django 4.0.3 on 2022-04-10 05:25

from django.db import migrations, models
import utils.rename


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_delete_contacts_alter_user_avatar_alter_user_bg_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='avatar',
            field=models.ImageField(blank=True, null=True, upload_to=utils.rename.Rename.rename, verbose_name='Аватар'),
        ),
        migrations.AlterField(
            model_name='user',
            name='bg',
            field=models.ImageField(blank=True, null=True, upload_to=utils.rename.Rename.rename, verbose_name='Задний фон'),
        ),
        migrations.AlterField(
            model_name='user',
            name='password',
            field=models.CharField(default='pbkdf2_sha256$320000$R09TwkFF7SDGmzakNB5qf2$cKOIshlwn2UVeVTU67jbNHcozimaPLLgwr1Nv9ll99w=', max_length=128, verbose_name='Пароль'),
        ),
        migrations.AlterField(
            model_name='userimage',
            name='image',
            field=models.ImageField(upload_to=utils.rename.Rename.rename, verbose_name='Изображение'),
        ),
    ]