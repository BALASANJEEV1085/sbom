package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// NewStorageClient creates a configured S3-compatible client from environment variables.
//
// Required env vars:
//
//	STORAGE_ENDPOINT        – e.g. https://s3.us-west-2.idrivee2.com
//	STORAGE_REGION          – e.g. us-west-2
//	STORAGE_ACCESS_KEY_ID
//	STORAGE_SECRET_ACCESS_KEY
func NewStorageClient() (*s3.Client, error) {
	endpoint := os.Getenv("STORAGE_ENDPOINT")
	region := os.Getenv("STORAGE_REGION")
	accessKey := os.Getenv("STORAGE_ACCESS_KEY_ID")
	secretKey := os.Getenv("STORAGE_SECRET_ACCESS_KEY")

	if endpoint == "" || region == "" || accessKey == "" || secretKey == "" {
		return nil, fmt.Errorf("storage: missing required environment variables (STORAGE_ENDPOINT, STORAGE_REGION, STORAGE_ACCESS_KEY_ID, STORAGE_SECRET_ACCESS_KEY)")
	}

	creds := credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")

	cfg := aws.Config{
		Region:      region,
		Credentials: creds,
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	return client, nil
}

// UploadFile uploads data to the given key under STORAGE_BUCKET_NAME.
//
// Recommended key format: sboms/{scanID}/{filename}
// contentType: "application/json" for CycloneDX, "text/plain" for SPDX.
func UploadFile(ctx context.Context, client *s3.Client, key string, data []byte, contentType string) error {
	bucket := os.Getenv("STORAGE_BUCKET_NAME")
	if bucket == "" {
		return fmt.Errorf("storage: STORAGE_BUCKET_NAME is not set")
	}

	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return fmt.Errorf("storage: upload %q failed: %w", key, err)
	}
	return nil
}

// GetPresignedURL generates a presigned GET URL for the given key.
// The URL expires after the provided duration.
func GetPresignedURL(ctx context.Context, client *s3.Client, key string, expiry time.Duration) (string, error) {
	bucket := os.Getenv("STORAGE_BUCKET_NAME")
	if bucket == "" {
		return "", fmt.Errorf("storage: STORAGE_BUCKET_NAME is not set")
	}

	presignClient := s3.NewPresignClient(client)

	req, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(expiry))
	if err != nil {
		return "", fmt.Errorf("storage: presign %q failed: %w", key, err)
	}

	return req.URL, nil
}

// DeleteFile removes an object from STORAGE_BUCKET_NAME.
func DeleteFile(ctx context.Context, client *s3.Client, key string) error {
	bucket := os.Getenv("STORAGE_BUCKET_NAME")
	if bucket == "" {
		return fmt.Errorf("storage: STORAGE_BUCKET_NAME is not set")
	}

	_, err := client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("storage: delete %q failed: %w", key, err)
	}
	return nil
}
