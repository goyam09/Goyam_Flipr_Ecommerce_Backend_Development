PGDMP  "    $        	    
    |         	   ecommerce    16.4    16.4 -    �           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            �           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            �           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            �           1262    32914 	   ecommerce    DATABASE     �   CREATE DATABASE ecommerce WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE ecommerce;
                postgres    false            �            1259    32953    carts    TABLE     �   CREATE TABLE public.carts (
    id integer NOT NULL,
    user_id integer,
    product_id integer,
    quantity integer DEFAULT 1
);
    DROP TABLE public.carts;
       public         heap    postgres    false            �            1259    32952    carts_id_seq    SEQUENCE     �   CREATE SEQUENCE public.carts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.carts_id_seq;
       public          postgres    false    220            �           0    0    carts_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.carts_id_seq OWNED BY public.carts.id;
          public          postgres    false    219            �            1259    32986    order_details    TABLE     �   CREATE TABLE public.order_details (
    id integer NOT NULL,
    order_id integer,
    product_id integer,
    quantity integer,
    price numeric(10,2)
);
 !   DROP TABLE public.order_details;
       public         heap    postgres    false            �            1259    32985    order_details_id_seq    SEQUENCE     �   CREATE SEQUENCE public.order_details_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 +   DROP SEQUENCE public.order_details_id_seq;
       public          postgres    false    224            �           0    0    order_details_id_seq    SEQUENCE OWNED BY     M   ALTER SEQUENCE public.order_details_id_seq OWNED BY public.order_details.id;
          public          postgres    false    223            �            1259    32971    orders    TABLE     �   CREATE TABLE public.orders (
    id integer NOT NULL,
    user_id integer,
    shipping_address text,
    total_amount numeric(10,2),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    status character varying(255)
);
    DROP TABLE public.orders;
       public         heap    postgres    false            �            1259    32970    orders_id_seq    SEQUENCE     �   CREATE SEQUENCE public.orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.orders_id_seq;
       public          postgres    false    222            �           0    0    orders_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;
          public          postgres    false    221            �            1259    32944    products    TABLE     �   CREATE TABLE public.products (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    category character varying(100)
);
    DROP TABLE public.products;
       public         heap    postgres    false            �            1259    32943    products_id_seq    SEQUENCE     �   CREATE SEQUENCE public.products_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.products_id_seq;
       public          postgres    false    218            �           0    0    products_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.products_id_seq OWNED BY public.products.id;
          public          postgres    false    217            �            1259    32933    users    TABLE     �   CREATE TABLE public.users (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    email character varying(100) NOT NULL,
    password character varying(255) NOT NULL,
    address text
);
    DROP TABLE public.users;
       public         heap    postgres    false            �            1259    32932    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public          postgres    false    216            �           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public          postgres    false    215            0           2604    32956    carts id    DEFAULT     d   ALTER TABLE ONLY public.carts ALTER COLUMN id SET DEFAULT nextval('public.carts_id_seq'::regclass);
 7   ALTER TABLE public.carts ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    220    219    220            4           2604    32989    order_details id    DEFAULT     t   ALTER TABLE ONLY public.order_details ALTER COLUMN id SET DEFAULT nextval('public.order_details_id_seq'::regclass);
 ?   ALTER TABLE public.order_details ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    224    223    224            2           2604    32974 	   orders id    DEFAULT     f   ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);
 8   ALTER TABLE public.orders ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    221    222    222            /           2604    32947    products id    DEFAULT     j   ALTER TABLE ONLY public.products ALTER COLUMN id SET DEFAULT nextval('public.products_id_seq'::regclass);
 :   ALTER TABLE public.products ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    217    218    218            .           2604    32936    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    215    216            �          0    32953    carts 
   TABLE DATA           B   COPY public.carts (id, user_id, product_id, quantity) FROM stdin;
    public          postgres    false    220   �1       �          0    32986    order_details 
   TABLE DATA           R   COPY public.order_details (id, order_id, product_id, quantity, price) FROM stdin;
    public          postgres    false    224   �1       �          0    32971    orders 
   TABLE DATA           a   COPY public.orders (id, user_id, shipping_address, total_amount, created_at, status) FROM stdin;
    public          postgres    false    222   �1       �          0    32944    products 
   TABLE DATA           J   COPY public.products (id, name, description, price, category) FROM stdin;
    public          postgres    false    218   o2       �          0    32933    users 
   TABLE DATA           C   COPY public.users (id, name, email, password, address) FROM stdin;
    public          postgres    false    216   �2       �           0    0    carts_id_seq    SEQUENCE SET     :   SELECT pg_catalog.setval('public.carts_id_seq', 3, true);
          public          postgres    false    219            �           0    0    order_details_id_seq    SEQUENCE SET     B   SELECT pg_catalog.setval('public.order_details_id_seq', 1, true);
          public          postgres    false    223            �           0    0    orders_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.orders_id_seq', 1, true);
          public          postgres    false    221            �           0    0    products_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.products_id_seq', 2, true);
          public          postgres    false    217            �           0    0    users_id_seq    SEQUENCE SET     :   SELECT pg_catalog.setval('public.users_id_seq', 1, true);
          public          postgres    false    215            <           2606    32959    carts carts_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.carts
    ADD CONSTRAINT carts_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.carts DROP CONSTRAINT carts_pkey;
       public            postgres    false    220            @           2606    32991     order_details order_details_pkey 
   CONSTRAINT     ^   ALTER TABLE ONLY public.order_details
    ADD CONSTRAINT order_details_pkey PRIMARY KEY (id);
 J   ALTER TABLE ONLY public.order_details DROP CONSTRAINT order_details_pkey;
       public            postgres    false    224            >           2606    32979    orders orders_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_pkey;
       public            postgres    false    222            :           2606    32951    products products_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.products
    ADD CONSTRAINT products_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.products DROP CONSTRAINT products_pkey;
       public            postgres    false    218            6           2606    32942    users users_email_key 
   CONSTRAINT     Q   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
 ?   ALTER TABLE ONLY public.users DROP CONSTRAINT users_email_key;
       public            postgres    false    216            8           2606    32940    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public            postgres    false    216            A           2606    32965    carts carts_product_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.carts
    ADD CONSTRAINT carts_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);
 E   ALTER TABLE ONLY public.carts DROP CONSTRAINT carts_product_id_fkey;
       public          postgres    false    4666    218    220            B           2606    32960    carts carts_user_id_fkey    FK CONSTRAINT     w   ALTER TABLE ONLY public.carts
    ADD CONSTRAINT carts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
 B   ALTER TABLE ONLY public.carts DROP CONSTRAINT carts_user_id_fkey;
       public          postgres    false    4664    220    216            D           2606    32992 )   order_details order_details_order_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.order_details
    ADD CONSTRAINT order_details_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.orders(id);
 S   ALTER TABLE ONLY public.order_details DROP CONSTRAINT order_details_order_id_fkey;
       public          postgres    false    224    222    4670            E           2606    32997 +   order_details order_details_product_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.order_details
    ADD CONSTRAINT order_details_product_id_fkey FOREIGN KEY (product_id) REFERENCES public.products(id);
 U   ALTER TABLE ONLY public.order_details DROP CONSTRAINT order_details_product_id_fkey;
       public          postgres    false    224    4666    218            C           2606    32980    orders orders_user_id_fkey    FK CONSTRAINT     y   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);
 D   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_user_id_fkey;
       public          postgres    false    222    4664    216            �      x�3�4�4�4����� ��      �      x�3�4�4�4�44500�30������ $e#      �   a   x��1� @ѹ���&HJA��Nn�Qb��$n�^����C����nԧ�gqգ�;�H��"���D-GL�JȜg7Jl#lE�KO�;c�>��      �   1   x�3�t,M��tJ-.QH-J��M�KN�445 =N�Ģb�=... -?�      �   �   x�3�tϯL�U�K�H,R�J����� �<��Cznbf�^r~.��Q�����iI�[�e��q��~�WxZHA���^����O�A��I@A�AEzER�AP�Jfiyn�?������sNjQ��s~N~^%W� �L(�     