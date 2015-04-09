﻿// ------------------------------------------------------------------------------
//  <auto-generated>
//    Generated by Xsd2Code. Version 3.4.0.32989
//    <NameSpace>MasterCard.SDK.Services.PartnerWallet.Domain.WalletStorage</NameSpace><Collection>List</Collection><codeType>CSharp</codeType><EnableDataBinding>False</EnableDataBinding><EnableLazyLoading>False</EnableLazyLoading><TrackingChangesEnable>False</TrackingChangesEnable><GenTrackingClasses>False</GenTrackingClasses><HidePrivateFieldInIDE>False</HidePrivateFieldInIDE><EnableSummaryComment>False</EnableSummaryComment><VirtualProp>False</VirtualProp><IncludeSerializeMethod>False</IncludeSerializeMethod><UseBaseClass>False</UseBaseClass><GenBaseClass>False</GenBaseClass><GenerateCloneMethod>False</GenerateCloneMethod><GenerateDataContracts>False</GenerateDataContracts><CodeBaseTag>Net20</CodeBaseTag><SerializeMethodName>Serialize</SerializeMethodName><DeserializeMethodName>Deserialize</DeserializeMethodName><SaveToFileMethodName>SaveToFile</SaveToFileMethodName><LoadFromFileMethodName>LoadFromFile</LoadFromFileMethodName><GenerateXMLAttributes>True</GenerateXMLAttributes><OrderXMLAttrib>False</OrderXMLAttrib><EnableEncoding>False</EnableEncoding><AutomaticProperties>False</AutomaticProperties><GenerateShouldSerialize>False</GenerateShouldSerialize><DisableDebug>False</DisableDebug><PropNameSpecified>Default</PropNameSpecified><Encoder>UTF8</Encoder><CustomUsings></CustomUsings><ExcludeIncludedTypes>False</ExcludeIncludedTypes><EnableInitializeFields>True</EnableInitializeFields>
//  </auto-generated>
// ------------------------------------------------------------------------------
namespace MasterCard.SDK.Services.PartnerWallet.Domain.WalletStorage
{
    using System;
    using System.Diagnostics;
    using System.Xml.Serialization;
    using System.Collections;
    using System.Xml.Schema;
    using System.ComponentModel;
    using System.Collections.Generic;


    [System.CodeDom.Compiler.GeneratedCodeAttribute("Xsd2Code", "3.4.0.32990")]
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true)]
    [System.Xml.Serialization.XmlRootAttribute(Namespace = "", IsNullable = false)]
    public partial class Wallet
    {

        private WalletCard cardField;

        public Wallet()
        {
            this.cardField = new WalletCard();
        }

        public WalletCard Card
        {
            get
            {
                return this.cardField;
            }
            set
            {
                this.cardField = value;
            }
        }
    }

    [System.CodeDom.Compiler.GeneratedCodeAttribute("Xsd2Code", "3.4.0.32990")]
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true)]
    public partial class WalletCard
    {

        private string idField;

        private string brandIDField;

        private long accountNumberField;

        private WalletCardBillingAddress billingAddressField;

        private string cardHolderNameField;

        private sbyte expiryMonthField;

        private short expiryYearField;

        public WalletCard()
        {
            this.billingAddressField = new WalletCardBillingAddress();
        }

        public string ID
        {
            get
            {
                return this.idField;
            }
            set
            {
                this.idField = value;
            }
        }

        public string BrandID
        {
            get
            {
                return this.brandIDField;
            }
            set
            {
                this.brandIDField = value;
            }
        }

        public long AccountNumber
        {
            get
            {
                return this.accountNumberField;
            }
            set
            {
                this.accountNumberField = value;
            }
        }

        public WalletCardBillingAddress BillingAddress
        {
            get
            {
                return this.billingAddressField;
            }
            set
            {
                this.billingAddressField = value;
            }
        }

        public string CardHolderName
        {
            get
            {
                return this.cardHolderNameField;
            }
            set
            {
                this.cardHolderNameField = value;
            }
        }

        public sbyte ExpiryMonth
        {
            get
            {
                return this.expiryMonthField;
            }
            set
            {
                this.expiryMonthField = value;
            }
        }

        public short ExpiryYear
        {
            get
            {
                return this.expiryYearField;
            }
            set
            {
                this.expiryYearField = value;
            }
        }
    }

    [System.CodeDom.Compiler.GeneratedCodeAttribute("Xsd2Code", "3.4.0.32990")]
    [System.SerializableAttribute()]
    [System.ComponentModel.DesignerCategoryAttribute("code")]
    [System.Xml.Serialization.XmlTypeAttribute(AnonymousType = true)]
    public partial class WalletCardBillingAddress
    {

        private string line1Field;

        private string cityField;

        private string countrySubdivisionField;

        private string countryField;

        private short postalCodeField;

        public string Line1
        {
            get
            {
                return this.line1Field;
            }
            set
            {
                this.line1Field = value;
            }
        }

        public string City
        {
            get
            {
                return this.cityField;
            }
            set
            {
                this.cityField = value;
            }
        }

        public string CountrySubdivision
        {
            get
            {
                return this.countrySubdivisionField;
            }
            set
            {
                this.countrySubdivisionField = value;
            }
        }

        public string Country
        {
            get
            {
                return this.countryField;
            }
            set
            {
                this.countryField = value;
            }
        }

        public short PostalCode
        {
            get
            {
                return this.postalCodeField;
            }
            set
            {
                this.postalCodeField = value;
            }
        }
    }
}