from django.db import models
from colorfield.fields import ColorField

from utils.rename import Rename

imageRename = Rename('images/cards');


class Card(models.Model):
    class Meta:
        verbose_name = "Карта";
        verbose_name_plural = "Карты";

    def __str__(self):
        return self.title;

    title = models.CharField(max_length=300, verbose_name="Название");
    color = ColorField(verbose_name="Цвет", format='hexa');
    text_color = ColorField(verbose_name="Цвет текста", format='hexa');
    image = models.ImageField(upload_to=imageRename.rename, verbose_name="Фото");
    price_dollar = models.FloatField(verbose_name="Цена в долларах");
    price_dirham = models.FloatField(verbose_name="Цена в дирхамах");
