from django.core.mail import BadHeaderError, send_mail
import uuid
import vobject
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.http import HttpResponse
from rest_framework import viewsets, permissions, status, generics
from rest_framework.decorators import parser_classes
from rest_framework.parsers import FormParser, FileUploadParser, MultiPartParser
from rest_framework.response import Response
from django.core.mail import send_mail
import datetime
from .serializers import SendMailSerializer, SendMessageSerializer
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenRefreshView

from users.models import User, UserImage
from users.serializers import (
    UserSerializer, UserCRUDSerializer, CustomTokenRefreshSerializer, UserImagesCRUDSerializer,
    UserImageSerializer, SendMessageSerializer,
    UserImageSerializer, UserAvatarFlipSerializer,
)
from utils.cropImage import cropImage
from utils.imgToBase64 import b64_image
from utils.main import generateError, generateAuthInfo
from constants.main import socials
from slugify import slugify
from rest_framework.generics import UpdateAPIView


class MVSDynamicPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if view.action == 'update':
            if request.user.is_authenticated:
                return True
            else:
                return False
        else:
            return True


class UserMVS(viewsets.ModelViewSet):
    queryset = User.objects.all();
    permission_classes = [MVSDynamicPermission]
    lookup_field = 'uniqueId'
    serializer_class = UserSerializer

    def create(self, request):
        secretAdminKey = request.data.get('secretAdminKey');
        if secretAdminKey == settings.SECRET_ADMIN_KEY:
            serializer = UserCRUDSerializer(data={'password': settings.DEFAULT_PASSWORD}, context={'request': request});
            serializer.is_valid(raise_exception=True);
            serializer.save();
            return Response(data=f"{settings.CLIENT_URL}/user/{serializer.data['uniqueId']}");
        return Response(status=status.HTTP_403_FORBIDDEN);

    def update(self, request, *args, **kwargs):
        user = request.user;
        data = request.data.dict();
        serializer = UserCRUDSerializer(user, data=data, context={'request': request});
        serializer.is_valid(raise_exception=True);
        serializer.save();
        return Response(serializer.data);


class UpdateUserAvatarView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request):
        user = request.user;
        image = cropImage(request);
        serializer = UserCRUDSerializer(user, data={"avatar": image}, partial=True)
        serializer.is_valid(raise_exception=True);
        serializer.save();
        userSerializer = UserSerializer(serializer.instance, context={'request': request});
        return Response(userSerializer.data);


class UserLoginView(generics.CreateAPIView):
    queryset = User.objects.all();
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        uniqueId = request.data.get('uniqueId');
        password = request.data.get('password');
        try:
            user = User.objects.get(uniqueId=uniqueId)
        except User.DoesNotExist:
            return Response(**generateError('DOES_NOT_EXIST'));
        checkPassword = check_password(password, user.password);
        if not checkPassword:
            return Response(**generateError('WRONG_PASSWORD'));
        serializer = self.serializer_class(user, context={'request': request});
        return Response(data=generateAuthInfo(user, serializer.data));


class ResetPasswordMVS(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserCRUDSerializer;
    lookup_field = 'resetPasswordUUID';

    def create(self, request, *args, **kwargs):
        uniqueId = request.data.get('uniqueId');
        try:
            user = User.objects.get(uniqueId=uniqueId);
        except User.DoesNotExist:
            return Response(**generateError('USER_NOT_FOUND'));
        serializer = self.serializer_class(user, context={'request': request});
        data = serializer.data;
        if not data['email']:
            return Response(**generateError('EMAIL_NOT_SET'));
        try:
            uuidStr = uuid.uuid4();
            milliseconds_since_epoch = datetime.datetime.now().timestamp() * 1000;
            user.resetPasswordUUID = uuidStr;
            user.resetPasswordDate = int(milliseconds_since_epoch) + 3600000;
            user.save();
            html_message = f'<a href="{settings.CLIENT_URL}/reset-password/{uuidStr}">Click me</a>';
            send_mail(
                'Reset password',
                'Click this button to reset password',
                settings.EMAIL_HOST_USER,
                [data['email']],
                fail_silently=False,
                html_message=html_message
            );
            return Response();
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR);

    def retrieve(self, request, *args, **kwargs):
        resetPasswordUUID = kwargs[self.lookup_field];
        try:
            user = User.objects.get(resetPasswordUUID=resetPasswordUUID);
        except User.DoesNotExist:
            return Response(**generateError('NOT_FOUND'));
        serializer = self.serializer_class(user, context={'request': request});
        milliseconds_since_epoch = datetime.datetime.now().timestamp() * 1000;
        if int(milliseconds_since_epoch) > serializer.data['resetPasswordDate']:
            return Response(**generateError('EXPIRED'));
        return Response(status=status.HTTP_200_OK);

    def update(self, request, *args, **kwargs):
        resetPasswordUUID = kwargs[self.lookup_field];
        password = request.data.get('password');
        try:
            user = User.objects.get(resetPasswordUUID=resetPasswordUUID);
        except User.DoesNotExist:
            return Response(**generateError('NOT_FOUND'));
        serializer = self.serializer_class(user, context={'request': request});
        milliseconds_since_epoch = datetime.datetime.now().timestamp() * 1000;
        if int(milliseconds_since_epoch) > serializer.data['resetPasswordDate']:
            return Response(**generateError('EXPIRED'));
        updateSerializer = self.serializer_class(user, data={'password': password, 'resetPasswordDate': None, 'resetPasswordUUID': None}, context={'request': request},partial=True);
        updateSerializer.is_valid(raise_exception=True);
        updateSerializer.save();
        serializer = UserSerializer(updateSerializer.instance, context={'request': request});
        return Response(data=generateAuthInfo(user, serializer.data), status=status.HTTP_200_OK);


class DownloadVCF(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'uniqueId'

    def retrieve(self, request, *args, **kwargs):
        user = self.queryset.get(uniqueId=kwargs[self.lookup_field]);
        user = self.serializer_class(user).data
        userSocials = []
        for key, value in user.items():
            if (key in socials) and (value is not None):
                userSocials.append((key, value))

        vCard = vobject.vCard()
        vCard.add('fn').value = user['fullname'] if user['fullname'] else ''
        # title field used for company name 
        company = vCard.add('org')
        company.value = user.get('title', '')
        company.type_param = 'ORG'
        vCard.add('email').value = user['email'] if user['email'] else ''

        if user['avatar']:
            base64 = b64_image(user['avatar']);
            if base64['success']:
                photo = vCard.add(f'PHOTO;ENCODING=b;TYPE=image/{base64["extension"]}')
                photo.value = base64['base64'];
        if user['address']:
            vCard.add('ADR').value = vobject.vcard.Address(
                street={user['address']},
                city="",
                region="",
                code="",
                country="",
                box="",
                extended="",
            );

        personalPhone = vCard.add('tel')
        personalPhone.type_param = "CELL"
        personalPhone.value = user['personalPhone'] if user['personalPhone'] else ''

        workPhone = vCard.add('tel')
        workPhone.value = user['workPhone'] if user['workPhone'] else ''
        workPhone.type_param = 'WORK'

        for social in userSocials:
            soc = vCard.add('url')
            soc.type_param = social[0]
            soc.value = social[1]

        fullnameSlug = slugify(user['fullname']) if user['fullname'] else None;
        filename = (fullnameSlug or user['email']) if (user['fullname'] or user['email']) else user['uniqueId'];
        response = HttpResponse(vCard.serialize(), content_type='text/x-vcard');
        response['Content-Disposition'] = f'attachment; filename={filename}.vcf';
        return response;


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = CustomTokenRefreshSerializer


class UserImagesMVS(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'uniqueId'
    serializer_class = UserImagesCRUDSerializer


class UserImageMVS(viewsets.ModelViewSet):
    queryset = UserImage.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'pk'
    serializer_class = UserImageSerializer


class SendMailAPIView(APIView):

    def post(self, request):

        serializer = SendMailSerializer(data=request.data)
        if serializer.is_valid():
            first_name = serializer.validated_data.get('first_name')
            last_name = serializer.validated_data.get('last_name')
            email = serializer.validated_data.get('email')
            message = serializer.validated_data.get('message')
            send_mail('',  from_email=None, message=f'{first_name} {last_name} {email} {message}', recipient_list=['temircard@gmail.com'])
            return Response(serializer.errors, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SendMailUserApiView(APIView):

    def post(self, request):

        serializer = SendMessageSerializer(data=request.data)
        if serializer.is_valid():
            first_name = serializer.validated_data.get('first_name')
            last_name = serializer.validated_data.get('last_name')
            mobile = serializer.validated_data.get('mobile')
            email = serializers.validated_data.get('email')

            city = serializers.validated_data.get('city')
            street = serializers.validated_data.get('street')
            building_name = serializers.validated_data.get('building_name')
            unit = serializers.validated_data.get('unit')
            description = serializers.validated_data.get('description')
            send_mail('', from_email=None, message=f'{first_name} {last_name} {email} {message} {mobile} {city} {street} {building_name} {unit} {description}',
                      recipient_list=['temircard@gmail.com'])
            return Response(serializer.errors, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ShowHideAvatarView(UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'uniqueId'
    serializer_class = UserAvatarFlipSerializer
