<?php

namespace Appwrite\Utopia\Response\Model;

use Appwrite\Utopia\Response;
use Appwrite\Utopia\Response\Model;

class File extends Model
{
    public function __construct()
    {
        $this
            ->addRule('$id', [
                'type' => self::TYPE_STRING,
                'description' => 'File ID.',
                'default' => '',
                'example' => '5e5ea5c16897e',
            ])
            ->addRule('bucketId', [
                'type' => self::TYPE_STRING,
                'description' => 'Bucket ID.',
                'default' => '',
                'example' => '5e5ea5c16897e',
            ])
            ->addRule('$createdAt', [
                'type' => self::TYPE_DATETIME,
                'description' => 'File creation date in Datetime',
                'default' => '',
                'example' => '1975-12-06 13:30:59',
            ])
            ->addRule('$updatedAt', [
                'type' => self::TYPE_DATETIME,
                'description' => 'File update date in Datetime',
                'default' => '',
                'example' => '1975-12-06 13:30:59',
            ])
            ->addRule('$read', [
                'type' => self::TYPE_STRING,
                'description' => 'File read permissions.',
                'default' => [],
                'example' => 'role:all',
                'array' => true,
            ])
            ->addRule('$write', [
                'type' => self::TYPE_STRING,
                'description' => 'File write permissions.',
                'default' => [],
                'example' => 'user:608f9da25e7e1',
                'array' => true,
            ])
            ->addRule('name', [
                'type' => self::TYPE_STRING,
                'description' => 'File name.',
                'default' => '',
                'example' => 'Pink.png',
            ])
            ->addRule('signature', [
                'type' => self::TYPE_STRING,
                'description' => 'File MD5 signature.',
                'default' => '',
                'example' => '5d529fd02b544198ae075bd57c1762bb',
            ])
            ->addRule('mimeType', [
                'type' => self::TYPE_STRING,
                'description' => 'File mime type.',
                'default' => '',
                'example' => 'image/png',
            ])
            ->addRule('sizeOriginal', [
                'type' => self::TYPE_INTEGER,
                'description' => 'File original size in bytes.',
                'default' => 0,
                'example' => 17890,
            ])
            ->addRule('chunksTotal', [
                'type' => self::TYPE_INTEGER,
                'description' => 'Total number of chunks available',
                'default' => 0,
                'example' => 17890,
            ])
            ->addRule('chunksUploaded', [
                'type' => self::TYPE_INTEGER,
                'description' => 'Total number of chunks uploaded',
                'default' => 0,
                'example' => 17890,
            ])
        ;
    }

    /**
     * Get Name
     *
     * @return string
     */
    public function getName(): string
    {
        return 'File';
    }

    /**
     * Get Type
     *
     * @return string
     */
    public function getType(): string
    {
        return Response::MODEL_FILE;
    }
}
